package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
)

var publicIP bool

func (i *Instance) preferredIP() string {
	if publicIP {
		return i.PublicIP
	}
	return i.PrivateIP
}

func ShowInstances(instances []*Instance) {
	builder := tablewriter.NewConfigBuilder().WithRowAlignment(tw.AlignRight)
	table := tablewriter.NewTable(os.Stderr, tablewriter.WithConfig(builder.Build()))
	table.Header([]string{
		"N", "ID", "Name", "S", "IP Addr", "Launch",
		"ICMP", "SSH", "HTTP", "HTTPS"})

	for n, i := range instances {
		row := []string{
			fmt.Sprint(n + 1), i.InstanceID[2:], i.Name(), i.PrettyState(),
			i.preferredIP(), fmtDuration(i.Up),
			(<-i.ICMPPing).String(),
			(<-i.SSHPing).String(),
			(<-i.HTTPPing).String(),
			(<-i.HTTPSPing).String(),
		}
		table.Append(row)
	}

	err := table.Render()
	if err != nil {
		log.Fatalf("Table render failed: %v", err)
	}
}

func GetInstanceFromUser(max int) int {
	s := bufio.NewScanner(os.Stdin)
	if !s.Scan() {
		// User closed stdin before we read anything
		os.Exit(1)
	}
	if s.Err() != nil {
		log.Fatalf("Error reading stdin: %v", s.Err())
	}
	var n int
	_, err := fmt.Sscan(s.Text(), &n)
	if err != nil {
		log.Fatalf("Unrecognised input: %v", s.Text())
	}
	if n > max {
		log.Fatalf("%q is not a valid instance", s.Text())
	}
	return n - 1
}

func InvokeSSH(bastion string, instance *Instance) {
	log.Printf("Connecting: %v", instance.Name())

	args := []string{"/usr/bin/ssh"}

	if bastion != "" {
		format := `ProxyCommand=ssh %v %v %%h %%p`
		// TODO(pwaller): automatically determine available netcat binary?
		netCat := "ncat"
		proxyCommand := fmt.Sprintf(format, bastion, netCat)
		args = append(args, "-o", proxyCommand)
	}

	// Enable the user to specify arguments to the left and right of the host.
	left, right := BreakArgsBySeparator()
	args = append(args, left...)
	args = append(args, instance.preferredIP())
	args = append(args, right...)

	err := syscall.Exec("/usr/bin/ssh", args, os.Environ())
	if err != nil {
		log.Fatalln("Failed to exec:", err)
	}
}

func CursorUp(n int) {
	fmt.Fprint(os.Stderr, "[", n, "F")
}
func ClearToEndOfScreen() {
	fmt.Fprint(os.Stderr, "[", "J")
}

func JumpTo(bastion string, s client.ConfigProvider, client *ec2.Client) {

	bastionID, err := ec2metadata.New(s).GetMetadata("instance-id")
	if err != nil {
		bastionID = ""
	}

	ec2Instances, err := client.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{})
	if err != nil {
		log.Fatal("DescribeInstances error:", err)
	}

	// Do this after querying the AWS endpoint (otherwise vulnerable to MITM.)
	ConfigureHTTP(false)

	instances := InstancesFromEC2Result(ec2Instances)
	bastionVPC := ""

	for _, i := range instances {
		if i.InstanceID == bastionID {
			bastionVPC = i.VPCID
		}
	}

	if bastionVPC != "" {
		instances = filterInstancesByVPC(instances, bastionVPC)
	}

	ShowInstances(instances)

	n := GetInstanceFromUser(len(instances))

	// +1 to account for final newline.
	CursorUp(len(instances) + N_TABLE_DECORATIONS + 1)
	ClearToEndOfScreen()

	InvokeSSH(bastion, instances[n])
}

func filterInstancesByVPC(instances []*Instance, vpcID string) []*Instance {
	filtered := []*Instance{}
	for _, instance := range instances {
		if instance.VPCID == vpcID {
			filtered = append(filtered, instance)
		}
	}
	return filtered
}

func Watch(c *ec2.Client) {

	finish := make(chan struct{})
	go func() {
		defer close(finish)
		// Await stdin closure
		io.Copy(ioutil.Discard, os.Stdin)
	}()

	goUp := func() {}

	for {
		queryStart := time.Now()
		ConfigureHTTP(true)

		ec2Instances, err := c.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{})
		if err != nil {
			log.Fatal("DescribeInstances error:", err)
		}

		ConfigureHTTP(false)

		instances := InstancesFromEC2Result(ec2Instances)

		goUp()

		ShowInstances(instances)

		queryDuration := time.Since(queryStart)

		select {
		case <-time.After(1*time.Second - queryDuration):
		case <-finish:
			return
		}
		goUp = func() { CursorUp(len(instances) + N_TABLE_DECORATIONS) }
	}

}

const N_TABLE_DECORATIONS = 4

func main() {
	var cfg aws.Config
	log.SetFlags(0)

	if os.Getenv("SSH_AUTH_SOCK") == "" {
		fmt.Fprintln(os.Stderr, "[41;1mWarning: agent forwarding not enabled[K[m")
	}

	if os.Getenv("JUMP_PUBLIC") != "" {
		publicIP = true
	}

	if os.Getenv("JUMP_BASTION") != "" {
		// Use the ssh connection to dial remotes
		bastionDialer, err := BastionDialer(os.Getenv("JUMP_BASTION"))
		if err != nil {
			log.Fatalf("BastionDialer: %v", err)
		}
		bastionTransport := &http.Transport{Dial: bastionDialer}

		bastionHTTPClient := http.Client{
			Transport: bastionTransport,
			Timeout:   30 * time.Second, // Set a reasonable timeout
		}

		// The EC2RoleProvider overrides the client configuration if
		// .HTTPClient == http.DefaultClient. Therefore, take a copy.
		// Also, have to re-initialise the default CredChain to make
		// use of HTTPClient set after session.New().
		// TODO: delete below commented lines
		//	useClient := *http.DefaultClient
		//	useClient.Transport = bastionTransport
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithHTTPClient(&bastionHTTPClient))
		if err != nil {
			log.Fatalf("Unable to load AWS config: %v", err)
		}

		// TODO: reuse IMDS client?
		imdsClient := imds.NewFromConfig(cfg)
		metadataOutput, err := imdsClient.GetMetadata(context.Background(), &imds.GetMetadataInput{Path: path})
		if err != nil {
			return "", err
		}
		defer metadataOutput.Content.Close()

		region, err := ec2metadata.New(s).Region()
		if err != nil {
			log.Printf("Unable to determine bastion region: %v", err)
		}
		// Make API calls from the bastion's region.
		s.Config.Region = aws.String(region)
	} else {
		var err error
		cfg, err = config.LoadDefaultConfig(context.Background())
		if err != nil {
			log.Fatalf("Unable to load AWS config: %v", err)
		}
	}

	svc := ec2.NewFromConfig(cfg)

	if len(os.Args) > 1 && os.Args[1] == "@" {
		Watch(svc)
		return
	}

	JumpTo(os.Getenv("JUMP_BASTION"), s, svc)
}

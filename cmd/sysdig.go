package main

import (
	"context"
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"dagger.io/dagger"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

func main() {
	ctx := context.Background()

	tenantId := os.Getenv("tenant-id")
	clientId := os.Getenv("client-id")
	keyvaultURL := os.Getenv("vault-uri")
	sysdigUri := os.Getenv("sysdig-url")

    secretName := "sysdig-api-token"
	image := os.Args[1]

	cred, err := azidentity.NewInteractiveBrowserCredential(&azidentity.InteractiveBrowserCredentialOptions{
		TenantID: tenantId,
		ClientID: clientId,
	})
	if err != nil {
		log.Fatal(err)
	}

	azclient, err := azsecrets.NewClient(keyvaultURL, cred, nil)
	if err != nil {
		log.Fatal(err)
	}

	secretBundle, err := azclient.GetSecret(context.Background(), secretName, "", nil)
	if err != nil {
		log.Fatal(err, "failed to get secret from keyvault", "keyvault", keyvaultURL, "secretName", secretName)
		os.Exit(1)
	}

	log.Print("successfully got secret")

	// initialize Dagger client
	client, err := dagger.Connect(ctx, dagger.WithLogOutput(os.Stdout))
	if err != nil {
		panic(err)
	}
	defer client.Close()

	golang := client.Container().From("quay.io/sysdig/secure-inline-scan:2").WithEnvVariable("SYSDIG_API_TOKEN", *secretBundle.Value).WithDefaultArgs(dagger.ContainerWithDefaultArgsOpts{
		Args: []string{
			"--sysdig-url",
			sysdigUri,
			image,
		},
	})

	_, err = golang.Stdout(ctx)
	if err != nil {
		panic(err)
	}
}

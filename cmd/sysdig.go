package main

import (
	"context"
	"log"
	"os"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"dagger.io/dagger"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

func main() {
	ctx := context.Background()

	tenantId := os.Getenv("TENANTID")
	clientId := os.Getenv("CLIENTID")
	clientSecret := os.Getenv("CLIENTSECRET")
	keyvaultURL := os.Getenv("VAULTURI")
	sysdigUri := os.Getenv("SYSDIGURI")
	ci := os.Getenv("CI")

    secretName := "sysdig-api-token"
	image := os.Args[1]

    var cred azcore.TokenCredential
    if b, err := strconv.ParseBool(ci); b {
        cred, err = azidentity.NewClientSecretCredential(tenantId, clientId, clientSecret, nil)
        if err != nil {
            log.Fatal(err)
        }
    } else {
        cred, err = azidentity.NewInteractiveBrowserCredential(&azidentity.InteractiveBrowserCredentialOptions{
            TenantID: tenantId,
            ClientID: clientId,
        })
        if err != nil {
            log.Fatal(err)
        }
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

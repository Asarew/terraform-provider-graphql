package graphql

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	restclient "k8s.io/client-go/rest"
)

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"service_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of the kubernetes service",
			},
			"service_namespace": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of the kubernetes service namespace",
			},
			"service_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of the kubernetes service namespace",
			},
			"host": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KUBE_HOST", ""),
				Description: "The hostname (in form of URI) of Kubernetes master.",
			},
			"username": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KUBE_USER", ""),
				Description: "The username to use for HTTP basic authentication when accessing the Kubernetes master endpoint.",
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KUBE_PASSWORD", ""),
				Description: "The password to use for HTTP basic authentication when accessing the Kubernetes master endpoint.",
			},
			"insecure": {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KUBE_INSECURE", false),
				Description: "Whether server should be accessed without verifying the TLS certificate.",
			},
			"client_certificate": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KUBE_CLIENT_CERT_DATA", ""),
				Description: "PEM-encoded client certificate for TLS authentication.",
			},
			"client_key": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KUBE_CLIENT_KEY_DATA", ""),
				Description: "PEM-encoded client certificate key for TLS authentication.",
			},
			"cluster_ca_certificate": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KUBE_CLUSTER_CA_CERT_DATA", ""),
				Description: "PEM-encoded root certificates bundle for TLS authentication.",
			},
			"config_paths": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "A list of paths to kube config files. Can be set with KUBE_CONFIG_PATHS environment variable.",
			},
			"config_path": {
				Type:          schema.TypeString,
				Optional:      true,
				DefaultFunc:   schema.EnvDefaultFunc("KUBE_CONFIG_PATH", nil),
				Description:   "Path to the kube config file. Can be set with KUBE_CONFIG_PATH.",
				ConflictsWith: []string{"config_paths"},
			},
			"config_context": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KUBE_CTX", ""),
			},
			"config_context_auth_info": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KUBE_CTX_AUTH_INFO", ""),
				Description: "",
			},
			"config_context_cluster": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KUBE_CTX_CLUSTER", ""),
				Description: "",
			},
			"token": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KUBE_TOKEN", ""),
				Description: "Token to authenticate an service account",
			},
			"proxy_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "URL to the proxy to be used for all API requests",
				DefaultFunc: schema.EnvDefaultFunc("KUBE_PROXY_URL", ""),
			},

			"url": {
				Required:    true,
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc("TF_GRAPHQL_URL", nil),
			},

			"headers": {
				Type: schema.TypeMap,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"oauth2_login_query": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"oauth2_login_query_variables": {
				Type: schema.TypeMap,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"oauth2_login_query_value_attribute": {
				Type:     schema.TypeString,
				Optional: true,
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"graphql_mutation": resourceGraphqlMutation(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"graphql_query": dataSourceGraphql(),
		},
		ConfigureContextFunc: graphqlConfigure,
	}
}

func graphqlConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	diags := diag.Diagnostics{}

	config := &graphqlProviderConfig{
		GQLServerUrl:   d.Get("url").(string),
		RequestHeaders: d.Get("headers").(map[string]interface{}),
	}

	cfg, err := initializeConfiguration(d)
	if err != nil {
		return nil, diag.FromErr(fmt.Errorf("unable to execute oauth2_login_query: %w", err))
	}

	config.Rest = cfg

	config.ServiceName = d.Get("service_name").(string)
	config.ServiceNamespace = d.Get("service_namespace").(string)

	oauth2LoginQuery := d.Get("oauth2_login_query").(string)
	oauth2LoginQueryVariables := d.Get("oauth2_login_query_variables").(map[string]interface{})
	oauth2LoginQueryValueAttribute := d.Get("oauth2_login_query_value_attribute").(string)

	if oauth2LoginQuery != "" && len(oauth2LoginQueryVariables) > 0 && oauth2LoginQueryValueAttribute != "" {
		queryResponse, _, err := queryExecute(ctx, d, config, "oauth2_login_query", "oauth2_login_query_variables")
		if err != nil {
			return nil, diag.FromErr(fmt.Errorf("unable to execute oauth2_login_query: %w", err))
		}

		if queryErrors := queryResponse.ProcessErrors(); queryErrors.HasError() {
			return nil, *queryErrors
		}

		var value string
		if value, err = getOAuth2LoginQueryAttributeValue(oauth2LoginQueryValueAttribute, queryResponse.Data); err != nil {
			return nil, diag.FromErr(err)
		}

		config.RequestAuthorizationHeaders = map[string]interface{}{
			"Authorization": fmt.Sprintf("Bearer %s", value),
		}
	} else if oauth2LoginQuery != "" || len(oauth2LoginQueryVariables) > 0 || oauth2LoginQueryValueAttribute != "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Incomplete OAuth 2.0 provider configuration",
			Detail:   "All three attributes must be set: `oauth2_login_query`, `oauth2_login_query_variables` and `oauth2_login_query_value_attribute`.",
		})
	}

	return config, diags
}

type graphqlProviderConfig struct {
	GQLServerUrl                string
	ServicePath                 string
	ServiceName                 string
	ServiceNamespace            string
	ServicePort                 string
	localProxy                  string
	Rest                        *restclient.Config
	RequestHeaders              map[string]interface{}
	RequestAuthorizationHeaders map[string]interface{}
}

func (cfg *graphqlProviderConfig) GetServerUrl(ctx context.Context) (string, error) {
	if cfg.GQLServerUrl != "" {
		return cfg.GQLServerUrl, nil
	}
	if cfg.localProxy != "" {
		return cfg.localProxy, nil
	}

	localPort, err := GetFreePort()
	if err != nil {
		return "", err
	}

	res, err := forwarders(ctx, []*Option{
		{
			LocalPort:   localPort,
			Namespace:   cfg.ServiceNamespace,
			ServiceName: cfg.ServiceName,
			RemotePort:  cfg.ServicePort,
		},
	}, cfg.Rest)
	if err != nil {
		return "", err
	}
	go res.Wait()

	return fmt.Sprintf("localhost:%d/%s", localPort, cfg.ServicePath), nil
}

func getOAuth2LoginQueryAttributeValue(attribute string, data map[string]interface{}) (string, error) {
	resourceKeyArgs := buildResourceKeyArgs(attribute)[1:] // Drop the leading `data` segment
	value, err := getResourceKey(data, resourceKeyArgs...)
	if err != nil {
		return "", err
	}
	return value.(string), nil
}

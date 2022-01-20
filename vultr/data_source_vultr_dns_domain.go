package vultr

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func dataSourceVultrDNSDomain() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceVultrDNSDomainRead,
		Schema: map[string]*schema.Schema{
			"domain": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "name of the domain",
				ValidateFunc: validation.NoZeroValues,
			},
			"date_created": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"dns_sec": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func dataSourceVultrDNSDomainRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*Client).govultrClient()

	domain, err := client.Domain.Get(ctx, d.Get("domain").(string))
	if err != nil {
		return diag.Errorf("error getting dns domains: %v", err)
	}

	d.SetId(domain.Domain)
	d.Set("domain", domain.Domain)
	d.Set("date_created", domain.DateCreated)
	d.Set("dns_sec", domain.DNSSec)
	return nil
}

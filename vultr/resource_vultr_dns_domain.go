package vultr

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/vultr/govultr/v2"
)

func resourceVultrDNSDomain() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceVultrDNSDomainCreate,
		ReadContext:   resourceVultrDNSDomainRead,
		UpdateContext: resourceVultrDNSDomainUpdate,
		DeleteContext: resourceVultrDNSDomainDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"domain": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},
			"ip": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				ValidateFunc: validation.IsIPAddress,
			},
			"dns_sec": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "disabled",
				ValidateFunc: validation.StringInSlice([]string{"disabled", "enabled"}, false),
			},
			"date_created": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceVultrDNSDomainCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*Client).govultrClient()

	domainReq := &govultr.DomainReq{
		Domain: d.Get("domain").(string),
		DNSSec: d.Get("dns_sec").(string),
	}

	if ip, ok := d.GetOk("ip"); ok {
		domainReq.IP = ip.(string)
	}

	log.Print("[INFO] Creating domain")

	domain, err := client.Domain.Create(ctx, domainReq)
	if err != nil {
		return diag.Errorf("error while creating domain : %s", err)
	}

	d.SetId(domain.Domain)

	return resourceVultrDNSDomainRead(ctx, d, meta)
}

func resourceVultrDNSDomainRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*Client).govultrClient()

	domain, err := client.Domain.Get(ctx, d.Id())
	if err != nil {
		return diag.Errorf("error getting domains : %v", err)
	}

	d.Set("domain", domain.Domain)
	d.Set("date_created", domain.DateCreated)
	d.Set("dns_sec", domain.DNSSec)

	return nil
}

func resourceVultrDNSDomainUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*Client).govultrClient()

	log.Printf("[INFO] Updated domain (%s)", d.Id())
	if err := client.Domain.Update(ctx, d.Id(), d.Get("dns_sec").(string)); err != nil {
		return diag.Errorf("error updating domain %s: %v", d.Id(), err)
	}

	return resourceVultrDNSDomainRead(ctx, d, meta)
}

func resourceVultrDNSDomainDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*Client).govultrClient()

	log.Printf("[INFO] Deleting domain (%s)", d.Id())
	if err := client.Domain.Delete(ctx, d.Id()); err != nil {
		return diag.Errorf("error destroying domain %s: %v", d.Id(), err)

	}

	return nil
}

package vultr

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/vultr/govultr/v2"
)

func dataSourceVultrReverseIPV4() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceVultrReverseIPV4Read,
		Schema: map[string]*schema.Schema{
			"filter": dataSourceFiltersSchema(),
			"instance_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ip": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"reverse": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"netmask": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"gateway": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func dataSourceVultrReverseIPV4Read(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	filters, filtersOk := d.GetOk("filter")

	if !filtersOk {
		return diag.Errorf("error getting filter: %v", filtersOk)
	}

	var instanceIDs []string

	for _, filter := range filters.(*schema.Set).List() {
		filterMap := filter.(map[string]interface{})

		name := filterMap["name"]
		values := filterMap["values"].([]interface{})

		if name == "instance_id" {
			for _, value := range values {
				instanceIDs = append(instanceIDs, value.(string))
			}
		}

		if name == "ip" {
			for i, value := range values {
				values[i] = value.(string)
			}
		}
	}

	client := meta.(*Client).govultrClient()

	// If the data source is not being filtered by `instance_id`, consider all instances
	options := &govultr.ListOptions{}
	if len(instanceIDs) == 0 {
		for {
			servers, meta, err := client.Instance.List(ctx, options)
			if err != nil {
				return diag.Errorf("error getting servers: %v", err)
			}

			for _, server := range servers {
				instanceIDs = append(instanceIDs, server.ID)
			}
			if meta.Links.Next == "" {
				break
			} else {
				options.Cursor = meta.Links.Next
				continue
			}
		}

	}

	filter := buildVultrDataSourceFilter(filters.(*schema.Set))
	var result *govultr.IPv4
	resultInstanceID := ""

	for _, instanceID := range instanceIDs {
		ipv4s, _, err := client.Instance.ListIPv4(ctx, instanceID, nil)
		if err != nil {
			return diag.Errorf("error getting IPv4s: %v", err)
		}

		for _, ipv4 := range ipv4s {
			m, err := structToMap(ipv4)
			if err != nil {
				return diag.FromErr(err)
			}

			if filterLoop(filter, m) {
				if result != nil {
					return diag.Errorf("your search returned too many results - please refine your search to be more specific")
				}

				result = &ipv4
				resultInstanceID = instanceID
			}
		}
	}

	if result == nil {
		return diag.Errorf("no results were found")
	}

	d.SetId(result.IP)
	d.Set("instance_id", resultInstanceID)
	d.Set("ip", result.IP)
	d.Set("reverse", result.Reverse)
	d.Set("netmask", result.Netmask)
	d.Set("gateway", result.Gateway)

	return nil
}

package vultr

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/vultr/govultr/v2"
)

func dataSourceVultrInstance() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceVultrInstanceRead,
		Schema: map[string]*schema.Schema{
			"filter": dataSourceFiltersSchema(),
			"os": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ram": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"disk": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"main_ip": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"vcpu_count": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"location": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"region": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"date_created": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"allowed_bandwidth": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"netmask_v4": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"gateway_v4": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"status": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"power_status": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"server_status": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"plan": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"v6_network": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"v6_main_ip": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"v6_network_size": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"label": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"internal_ip": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"kvm": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"backups": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"tag": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"os_id": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"app_id": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"image_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"firewall_group_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"features": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
			},
			"backups_schedule": {
				Type:     schema.TypeMap,
				Computed: true,
			},
			"hostname": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"private_network_ids": {
				Type:     schema.TypeList,
				Computed: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceVultrInstanceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*Client).govultrClient()

	filters, filtersOk := d.GetOk("filter")

	if !filtersOk {
		return diag.Errorf("issue with filter: %v", filtersOk)
	}

	var serverList []govultr.Instance
	f := buildVultrDataSourceFilter(filters.(*schema.Set))
	options := &govultr.ListOptions{}
	for {
		servers, meta, err := client.Instance.List(ctx, options)
		if err != nil {
			return diag.Errorf("error getting servers: %v", err)
		}

		for _, s := range servers {
			// we need convert the a struct INTO a map so we can easily manipulate the data here
			sm, err := structToMap(s)

			if err != nil {
				return diag.FromErr(err)
			}

			if filterLoop(f, sm) {
				serverList = append(serverList, s)
			}
		}

		if meta.Links.Next == "" {
			break
		} else {
			options.Cursor = meta.Links.Next
			continue
		}
	}

	if len(serverList) > 1 {
		return diag.Errorf("your search returned too many results. Please refine your search to be more specific")
	}

	if len(serverList) < 1 {
		return diag.Errorf("no results were found")
	}

	d.SetId(serverList[0].ID)
	d.Set("os", serverList[0].Os)
	d.Set("ram", serverList[0].RAM)
	d.Set("disk", serverList[0].Disk)
	d.Set("main_ip", serverList[0].MainIP)
	d.Set("vcpu_count", serverList[0].VCPUCount)
	d.Set("region", serverList[0].Region)
	d.Set("date_created", serverList[0].DateCreated)
	d.Set("allowed_bandwidth", serverList[0].AllowedBandwidth)
	d.Set("netmask_v4", serverList[0].NetmaskV4)
	d.Set("gateway_v4", serverList[0].GatewayV4)
	d.Set("status", serverList[0].Status)
	d.Set("power_status", serverList[0].PowerStatus)
	d.Set("server_status", serverList[0].ServerStatus)
	d.Set("plan", serverList[0].Plan)
	d.Set("label", serverList[0].Label)
	d.Set("internal_ip", serverList[0].InternalIP)
	d.Set("kvm", serverList[0].KVM)
	d.Set("tag", serverList[0].Tag)
	d.Set("os_id", serverList[0].OsID)
	d.Set("app_id", serverList[0].AppID)
	d.Set("image_id", serverList[0].ImageID)
	d.Set("firewall_group_id", serverList[0].FirewallGroupID)
	d.Set("v6_network", serverList[0].V6Network)
	d.Set("v6_main_ip", serverList[0].V6MainIP)
	d.Set("v6_network_size", serverList[0].V6NetworkSize)
	d.Set("features", serverList[0].Features)
	d.Set("hostname", serverList[0].Hostname)

	schedule, err := client.Instance.GetBackupSchedule(ctx, serverList[0].ID)
	if err != nil {
		return diag.Errorf("error getting backup schedule: %v", err)
	}
	d.Set("backups", backupStatus(schedule.Enabled))

	bsInfo := map[string]interface{}{
		"type": schedule.Type,
		"hour": strconv.Itoa(schedule.Hour),
		"dom":  strconv.Itoa(schedule.Dom),
		"dow":  strconv.Itoa(schedule.Dow),
	}
	if err := d.Set("backups_schedule", bsInfo); err != nil {
		return diag.Errorf("error setting `backups_schedule`: %#v", err)
	}

	pn, err := getPrivateNetworks(client, d.Id())
	if err != nil {
		return diag.Errorf(err.Error())
	}

	d.Set("private_network_ids", pn)

	return nil
}

package vultr

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/vultr/govultr/v2"
)

func dataSourceVultrBlockStorage() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceVultrBlockStorageRead,
		Schema: map[string]*schema.Schema{
			"filter": dataSourceFiltersSchema(),
			"date_created": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"cost": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"status": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"size_gb": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"region": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"attached_to_instance": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"label": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"mount_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func dataSourceVultrBlockStorageRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*Client).govultrClient()

	filters, filtersOk := d.GetOk("filter")

	if !filtersOk {
		return fmt.Errorf("issue with filter: %v", filtersOk)
	}

	var blockList []govultr.BlockStorage
	f := buildVultrDataSourceFilter(filters.(*schema.Set))
	options := &govultr.ListOptions{}
	for {
		block, meta, err := client.BlockStorage.List(context.Background(), options)
		if err != nil {
			return fmt.Errorf("error getting block storages: %v", err)
		}

		for _, b := range block {
			sm, err := structToMap(b)

			if err != nil {
				return err
			}

			if filterLoop(f, sm) {
				blockList = append(blockList, b)
			}
		}

		if meta.Links.Next == "" {
			break
		} else {
			options.Cursor = meta.Links.Next
			continue
		}
	}
	if len(blockList) > 1 {
		return errors.New("your search returned too many results. Please refine your search to be more specific")
	}

	if len(blockList) < 1 {
		return errors.New("no results were found")
	}

	d.SetId(blockList[0].ID)
	d.Set("date_created", blockList[0].DateCreated)
	d.Set("cost", blockList[0].Cost)
	d.Set("status", blockList[0].Status)
	d.Set("size_gb", blockList[0].SizeGB)
	d.Set("region", blockList[0].Region)
	d.Set("attached_to_instance", blockList[0].AttachedToInstance)
	d.Set("label", blockList[0].Label)
	d.Set("mount_id", blockList[0].MountID)
	return nil
}

package vultr

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/vultr/govultr/v3"
)

func resourceVultrBareMetalServer() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceVultrBareMetalServerCreate,
		ReadContext:   resourceVultrBareMetalServerRead,
		UpdateContext: resourceVultrBareMetalServerUpdate,
		DeleteContext: resourceVultrBareMetalServerDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			// Required
			"region": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				DiffSuppressFunc: IgnoreCase,
			},
			"plan": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			// Optional
			"label": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "",
			},
			"tags": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Default:  nil,
			},
			"script_id": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "",
			},
			"persistent_pxe": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
			},
			"snapshot_id": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"enable_ipv6": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
			},
			"vpc2_ids": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"ssh_key_ids": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Default:  nil,
			},
			"user_data": {
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
				ForceNew: true,
			},
			"activation_email": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"hostname": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "",
			},
			"os_id": {
				Type:     schema.TypeInt,
				Computed: true,
				Optional: true,
			},
			"app_id": {
				Type:     schema.TypeInt,
				Computed: true,
				Optional: true,
			},
			"image_id": {
				Type:     schema.TypeString,
				Computed: true,
				ForceNew: true,
				Optional: true,
			},
			"reserved_ipv4": {
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
			},
			"user_scheme": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "root",
			},
			"app_variables": {
				Type:     schema.TypeMap,
				Optional: true,
				ForceNew: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"mdisk_mode": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "",
			},
			// Computed
			"os": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ram": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"disk": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"main_ip": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"cpu_count": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"default_password": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"date_created": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"status": {
				Type:     schema.TypeString,
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
			"mac_address": {
				Type:     schema.TypeInt,
				Computed: true,
			},
		},

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(1 * time.Hour),
			Update: schema.DefaultTimeout(1 * time.Hour),
		},
	}
}

func resourceVultrBareMetalServerCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics { //nolint:lll
	appID, appOK := d.GetOk("app_id")
	osID, osOK := d.GetOk("os_id")
	imageID, imageOK := d.GetOk("image_id")
	snapshotID, snapshotOK := d.GetOk("snapshot_id")

	osOptions := map[string]bool{"os_id": osOK, "app_id": appOK, "snapshot_id": snapshotOK, "image_id": imageOK}
	osOption, err := bareMetalServerOSCheck(osOptions)
	if err != nil {
		return diag.FromErr(err)
	}

	keyIDs := make([]string, d.Get("ssh_key_ids.#").(int))
	for i, id := range d.Get("ssh_key_ids").([]interface{}) {
		keyIDs[i] = id.(string)
	}

	req := &govultr.BareMetalCreate{
		Region:          d.Get("region").(string),
		Plan:            d.Get("plan").(string),
		StartupScriptID: d.Get("script_id").(string),
		EnableIPv6:      govultr.BoolToBoolPtr(d.Get("enable_ipv6").(bool)),
		Label:           d.Get("label").(string),
		SSHKeyIDs:       keyIDs,
		UserData:        base64.StdEncoding.EncodeToString([]byte(d.Get("user_data").(string))),
		ActivationEmail: govultr.BoolToBoolPtr(d.Get("activation_email").(bool)),
		Hostname:        d.Get("hostname").(string),
		ReservedIPv4:    d.Get("reserved_ipv4").(string),
		PersistentPxe:   govultr.BoolToBoolPtr(d.Get("persistent_pxe").(bool)),
		MdiskMode:       d.Get("mdisk_mode").(string),
		UserScheme:      d.Get("user_scheme").(string),
	}

	if appVariables, appVariablesOK := d.GetOk("app_variables"); appVariablesOK {
		appVariablesMap := make(map[string]string)
		for k, v := range appVariables.(map[string]interface{}) {
			appVariablesMap[k] = v.(string)
		}
		req.AppVariables = appVariablesMap
	}

	switch osOption {
	case "app_id":
		req.AppID = appID.(int)
	case "snapshot_id":
		req.SnapshotID = snapshotID.(string)
	case "os_id":
		req.OsID = osID.(int)
	case "image_id":
		req.ImageID = imageID.(string)
	}

	if tagsIDs, tagsOK := d.GetOk("tags"); tagsOK {
		for _, v := range tagsIDs.(*schema.Set).List() {
			req.Tags = append(req.Tags, v.(string))
		}
	}

	if vpcIDs, vpcOK := d.GetOk("vpc2_ids"); vpcOK {
		for _, v := range vpcIDs.([]interface{}) {
			req.AttachVPC2 = append(req.AttachVPC2, v.(string))
		}
	}

	client := meta.(*Client).govultrClient()

	bm, _, err := client.BareMetalServer.Create(ctx, req)
	if err != nil {
		return diag.Errorf("error creating bare metal server: %v", err)
	}

	d.SetId(bm.ID)
	log.Printf("[INFO] Bare Metal Server ID: %s", d.Id())

	if _, err = waitForBareMetalServerActiveStatus(ctx, d, meta); err != nil {
		return diag.Errorf("error while waiting for bare metal server (%s) to be in active state: %s", d.Id(), err)
	}

	return resourceVultrBareMetalServerRead(ctx, d, meta)
}

func resourceVultrBareMetalServerRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*Client).govultrClient()

	bms, _, err := client.BareMetalServer.Get(ctx, d.Id())
	if err != nil {
		if strings.Contains(err.Error(), "Invalid server") {
			log.Printf("[WARN] Removing bare metal server %s because it is gone", d.Id())
			d.SetId("")
			return nil
		}
		return diag.Errorf("error getting bare metal server: %v", err)
	}

	d.SetId(bms.ID)
	if err := d.Set("os", bms.Os); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `os` read value: %v", err)
	}
	if err := d.Set("ram", bms.RAM); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `ram` read value: %v", err)
	}
	if err := d.Set("disk", bms.Disk); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `disk` read value: %v", err)
	}
	if err := d.Set("main_ip", bms.MainIP); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `main_ip` read value: %v", err)
	}
	if err := d.Set("cpu_count", bms.CPUCount); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `cpu_count` read value: %v", err)
	}
	if err := d.Set("region", bms.Region); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `region` read value: %v", err)
	}
	if err := d.Set("default_password", bms.DefaultPassword); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `default_password` read value: %v", err)
	}
	if err := d.Set("date_created", bms.DateCreated); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `date_created` read value: %v", err)
	}
	if err := d.Set("status", bms.Status); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `status` read value: %v", err)
	}
	if err := d.Set("netmask_v4", bms.NetmaskV4); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `netmask_v4` read value: %v", err)
	}
	if err := d.Set("gateway_v4", bms.GatewayV4); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `gateway_v4` read value: %v", err)
	}
	if err := d.Set("plan", bms.Plan); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `plan` read value: %v", err)
	}
	if err := d.Set("label", bms.Label); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `label` read value: %v", err)
	}
	if err := d.Set("tags", bms.Tags); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `tags` read value: %v", err)
	}
	if err := d.Set("mac_address", bms.MacAddress); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `mac_address` read value: %v", err)
	}
	if err := d.Set("os_id", bms.OsID); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `os_id` read value: %v", err)
	}
	if err := d.Set("app_id", bms.AppID); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `app_id` read value: %v", err)
	}
	if err := d.Set("image_id", bms.ImageID); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `image_id` read value: %v", err)
	}
	if err := d.Set("v6_network", bms.V6Network); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `v6_network` read value: %v", err)
	}
	if err := d.Set("v6_main_ip", bms.V6MainIP); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `v6_main_ip` read value: %v", err)
	}
	if err := d.Set("v6_network_size", bms.V6NetworkSize); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `v6_network_size` read value: %v", err)
	}
	if err := d.Set("user_scheme", bms.UserScheme); err != nil {
		return diag.Errorf("unable to set resource bare_metal_server `user_scheme` read value: %v", err)
	}

	vpc2s, err := getBareMetalServerVPC2s(client, d.Id())
	if err != nil {
		return diag.Errorf("%s", err.Error())
	}

	if _, vpcUpdate := d.GetOk("vpc2_ids"); vpcUpdate {
		if err := d.Set("vpc2_ids", vpc2s); err != nil {
			return diag.Errorf("unable to set resource instance `vpc2_ids` read value: %v", err)
		}
	}

	return nil
}

func resourceVultrBareMetalServerUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics { //nolint:lll
	client := meta.(*Client).govultrClient()

	req := &govultr.BareMetalUpdate{
		Label:      d.Get("label").(string),
		Tags:       []string{},
		EnableIPv6: govultr.BoolToBoolPtr(d.Get("enable_ipv6").(bool)),
	}

	if d.HasChange("app_id") {
		log.Printf(`[INFO] Changing bare metal server (%s) application`, d.Id())
		_, newVal := d.GetChange("app_id")

		appID := newVal.(int)
		req.AppID = appID
	}

	if d.HasChange("os_id") {
		log.Printf(`[INFO] Changing bare metal server (%s) operating system`, d.Id())
		_, newVal := d.GetChange("os_id")

		osID := newVal.(int)
		req.OsID = osID
	}

	if d.HasChange("vpc2_ids") {
		log.Printf("[INFO] Updating vpc2_ids")
		oldVPC, newVPC := d.GetChange("vpc2_ids")

		var oldIDs []string
		for _, v := range oldVPC.([]interface{}) {
			oldIDs = append(oldIDs, v.(string))
		}

		var newIDs []string
		for _, v := range newVPC.([]interface{}) {
			newIDs = append(newIDs, v.(string))
		}

		req.AttachVPC2 = append(req.AttachVPC2, diffSlice(oldIDs, newIDs)...)
		req.DetachVPC2 = append(req.DetachVPC2, diffSlice(newIDs, oldIDs)...)
	}

	if d.HasChange("tags") {
		_, newTags := tfChangeToSlices("tags", d)
		req.Tags = newTags
	}

	if d.HasChange("user_scheme") {
		_, newVal := d.GetChange("user_scheme")
		uScheme := newVal.(string)
		req.UserScheme = uScheme
	}

	if _, _, err := client.BareMetalServer.Update(ctx, d.Id(), req); err != nil {
		return diag.Errorf("error updating bare metal %s : %s", d.Id(), err.Error())
	}

	return resourceVultrBareMetalServerRead(ctx, d, meta)
}

func resourceVultrBareMetalServerDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics { //nolint:lll
	client := meta.(*Client).govultrClient()

	log.Printf("[INFO] Deleting bare metal server: %s", d.Id())

	if vpcIDs, vpcOK := d.GetOk("vpc2_ids"); vpcOK {
		detach := &govultr.BareMetalUpdate{}
		for _, v := range vpcIDs.([]interface{}) {
			detach.DetachVPC2 = append(detach.DetachVPC2, v.(string))
		}

		if _, _, err := client.BareMetalServer.Update(ctx, d.Id(), detach); err != nil {
			return diag.Errorf("error detaching VPC2s prior to deleting bare-metal server %s : %v", d.Id(), err)
		}
	}

	if err := client.BareMetalServer.Delete(ctx, d.Id()); err != nil {
		return diag.Errorf("error deleting bare metal server (%s): %v", d.Id(), err)
	}

	return nil
}

func bareMetalServerOSCheck(options map[string]bool) (string, error) {
	var result []string
	for k, v := range options {
		if v {
			result = append(result, k)
		}
	}

	if len(result) > 1 {
		return "", fmt.Errorf("too many OS options have been selected: %v - please select one", result)
	}
	if len(result) == 0 {
		return "", errors.New("you must set one of the following: os_id, app_id, or snapshot_id")
	}

	return result[0], nil
}

func waitForBareMetalServerActiveStatus(ctx context.Context, d *schema.ResourceData, meta interface{}) (interface{}, error) { //nolint:lll
	log.Printf("[INFO] Waiting for bare metal server (%s) to have status of active", d.Id())

	stateConf := &retry.StateChangeConf{
		Pending:    []string{"pending"},
		Target:     []string{"active"},
		Refresh:    newBareMetalServerStatusStateRefresh(ctx, d, meta),
		Timeout:    60 * time.Minute,
		Delay:      10 * time.Second,
		MinTimeout: 3 * time.Second,

		NotFoundChecks: 60,
	}

	return stateConf.WaitForStateContext(ctx)
}

func newBareMetalServerStatusStateRefresh(ctx context.Context, d *schema.ResourceData, meta interface{}) retry.StateRefreshFunc { //nolint:lll
	client := meta.(*Client).govultrClient()

	return func() (interface{}, string, error) {
		bms, _, err := client.BareMetalServer.Get(ctx, d.Id())
		if err != nil {
			return nil, "", fmt.Errorf("error retrieving bare metal server %s : %s", d.Id(), err)
		}

		log.Printf("[INFO] Bare metal server (%s) status: %s", d.Id(), bms.Status)
		return bms, bms.Status, nil
	}
}

package vultr

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/vultr/govultr/v3"
)

func resourceVultrInstance() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceVultrInstanceCreate,
		ReadContext:   resourceVultrInstanceRead,
		UpdateContext: resourceVultrInstanceUpdate,
		DeleteContext: resourceVultrInstanceDelete,
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
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.NoZeroValues,
			},
			// Optional
			"iso_id": {
				Type:     schema.TypeString,
				Default:  "",
				Optional: true,
			},
			"app_id": {
				Type:     schema.TypeInt,
				Computed: true,
				Optional: true,
				ForceNew: true,
			},
			"image_id": {
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
				ForceNew: true,
			},
			"os_id": {
				Type:     schema.TypeInt,
				Computed: true,
				Optional: true,
				ForceNew: true,
			},
			"script_id": {
				Type:     schema.TypeString,
				Computed: true,
				ForceNew: true,
				Optional: true,
			},
			"enable_ipv6": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"disable_public_ipv4": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
				Description: `Don't set up a public IPv4 address when IPv6 is enabled. 
Will not do anything unless enable_ipv6 is also true.`,
			},
			"vpc_ids": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"vpc2_ids": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"label": {
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
			},
			"ssh_key_ids": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"snapshot_id": {
				Type:     schema.TypeString,
				Computed: true,
				ForceNew: true,
				Optional: true,
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
			"ddos_protection": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"hostname": {
				Type:     schema.TypeString,
				ForceNew: true,
				Computed: true,
				Optional: true,
				Description: `The hostname of the instance. Updating the
hostname will cause a force new. This behavior is in place to prevent accidental reinstalls. Issuing an update to the
hostname on UI or API issues a reinstall of the OS.`,
			},
			"tags": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Default:  nil,
			},
			"reserved_ip_id": {
				Type:     schema.TypeString,
				ForceNew: true,
				Computed: true,
				Optional: true,
			},
			"firewall_group_id": {
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
			},
			"backups": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "disabled",
				ValidateFunc: validation.StringInSlice([]string{"enabled", "disabled"}, false),
			},
			"backups_schedule": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"type": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.StringInSlice(
								[]string{
									"daily",
									"weekly",
									"monthly",
									"daily_alt_even",
									"daily_alt_odd",
								},
								false,
							),
						},
						"hour": {
							Type:     schema.TypeInt,
							Optional: true,
							Computed: true,
						},
						"dow": {
							Type:     schema.TypeInt,
							Optional: true,
							Computed: true,
						},
						"dom": {
							Type:     schema.TypeInt,
							Optional: true,
							Computed: true,
						},
					},
				},
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
			// Computed
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
			"power_status": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"server_status": {
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
			"internal_ip": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"kvm": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"features": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Computed: true,
			},
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(1 * time.Hour),
			Update: schema.DefaultTimeout(1 * time.Hour),
		},
	}
}

func resourceVultrInstanceCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// five unique options to image your server
	osID := d.Get("os_id")
	appID, appOK := d.GetOk("app_id")
	imageID, imageOK := d.GetOk("image_id")
	isoID, isoOK := d.GetOk("iso_id")
	snapID, snapOK := d.GetOk("snapshot_id")
	backups := d.Get("backups").(string)
	backupSchedule, backupsScheduleOk := d.GetOk("backups_schedule")

	if backups == "enabled" && !backupsScheduleOk {
		return diag.Errorf("Backups are set to enabled please provide a backups_schedule")
	} else if backups == "disabled" && backupsScheduleOk {
		return diag.Errorf("Backups are set to disabled please remove backups_schedule")
	}

	osOptions := map[string]bool{"app_id": appOK, "iso_id": isoOK, "snapshot_id": snapOK, "image_id": imageOK}
	osOption, err := optionCheck(osOptions)
	if err != nil {
		return diag.FromErr(err)
	}

	client := meta.(*Client).govultrClient()

	req := &govultr.InstanceCreateReq{
		EnableIPv6:        govultr.BoolToBoolPtr(d.Get("enable_ipv6").(bool)),
		DisablePublicIPv4: govultr.BoolToBoolPtr(d.Get("disable_public_ipv4").(bool)),
		Label:             d.Get("label").(string),
		Backups:           backups,
		UserData:          base64.StdEncoding.EncodeToString([]byte(d.Get("user_data").(string))),
		ActivationEmail:   govultr.BoolToBoolPtr(d.Get("activation_email").(bool)),
		DDOSProtection:    govultr.BoolToBoolPtr(d.Get("ddos_protection").(bool)),
		Hostname:          d.Get("hostname").(string),
		FirewallGroupID:   d.Get("firewall_group_id").(string),
		ScriptID:          d.Get("script_id").(string),
		ReservedIPv4:      d.Get("reserved_ip_id").(string),
		Region:            d.Get("region").(string),
		Plan:              d.Get("plan").(string),
		UserScheme:        d.Get("user_scheme").(string),
	}

	if appVariables, appVariablesOK := d.GetOk("app_variables"); appVariablesOK {
		appVariablesMap := make(map[string]string)
		for k, v := range appVariables.(map[string]interface{}) {
			appVariablesMap[k] = v.(string)
		}
		req.AppVariables = appVariablesMap
	}

	// If no osOptions where selected and osID has a real value then set the osOptions to osID
	if osOption == "" && osID.(int) != 0 {
		osOption = "os_id"
	} else if osOption != "" && osID.(int) != 0 {
		return diag.Errorf("Please do not set %s with os_id", osOption)
	}

	switch osOption {
	case "os_id":
		req.OsID = osID.(int)
	case "app_id":
		req.AppID = appID.(int)
	case "image_id":
		req.ImageID = imageID.(string)
	case "iso_id":
		req.ISOID = isoID.(string)
	case "snapshot_id":
		req.SnapshotID = snapID.(string)
	default:
		return diag.Errorf("error occurred while getting your intended os type")
	}

	if tagsIDs, tagsOK := d.GetOk("tags"); tagsOK {
		for _, v := range tagsIDs.(*schema.Set).List() {
			req.Tags = append(req.Tags, v.(string))
		}
	}

	if vpcIDs, vpcOK := d.GetOk("vpc_ids"); vpcOK {
		for _, v := range vpcIDs.([]interface{}) {
			req.AttachVPC = append(req.AttachVPC, v.(string))
		}
	}

	if vpcIDs, vpcOK := d.GetOk("vpc2_ids"); vpcOK {
		for _, v := range vpcIDs.([]interface{}) {
			req.AttachVPC2 = append(req.AttachVPC2, v.(string))
		}
	}

	if sshKeyIDs, sshKeyOK := d.GetOk("ssh_key_ids"); sshKeyOK {
		for _, v := range sshKeyIDs.([]interface{}) {
			req.SSHKeys = append(req.SSHKeys, v.(string))
		}
	}

	log.Printf("[INFO] Creating server")
	var instance *govultr.Instance = nil

	// allow for retries on creation to handle retryable platform errors
	retryErr := retry.RetryContext(ctx, d.Timeout(schema.TimeoutCreate)-time.Minute, func() *retry.RetryError {
		instanceData, _, err := client.Instance.Create(ctx, req)
		instance = instanceData

		if err == nil {
			return nil
		}

		if strings.Contains(err.Error(), "Floating IPv4 address is already attached to another server") {
			return retry.RetryableError(fmt.Errorf("cannot create instance with reserved IP: %s", err.Error()))
		}

		return retry.NonRetryableError(err)
	})

	if retryErr != nil {
		return diag.Errorf("error creating server: %v", retryErr)
	}

	d.SetId(instance.ID)
	if err := d.Set("default_password", instance.DefaultPassword); err != nil {
		return diag.Errorf("unable to set resource instance `default_password` create value: %v", err)
	}

	_, err = waitForServerAvailable(ctx, d, "active", []string{"pending", "installing"}, "status", meta)
	if err != nil {
		return diag.Errorf("error while waiting for Server %s to be completed: %s", d.Id(), err)
	}

	if _, err = waitForServerAvailable(ctx, d, "running", []string{"stopped"}, "power_status", meta); err != nil {
		return diag.Errorf("error while waiting for Server %s to be in a active state : %s", d.Id(), err)
	}

	if backups == "enabled" {
		backupReq := generateBackupSchedule(backupSchedule)
		if _, err := client.Instance.SetBackupSchedule(context.Background(), instance.ID, backupReq); err != nil {
			return diag.Errorf("error setting backup schedule: %v", err)
		}
	}

	return resourceVultrInstanceRead(ctx, d, meta)
}

func resourceVultrInstanceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*Client).govultrClient()

	instance, _, err := client.Instance.Get(ctx, d.Id())
	if err != nil {
		if strings.Contains(err.Error(), "invalid instance ID") {
			log.Printf("[WARN] Removing instance (%s) because it is gone", d.Id())
			d.SetId("")
			return nil
		}
		return diag.Errorf("error getting instance (%s): %v", d.Id(), err)
	}

	if err := d.Set("os", instance.Os); err != nil {
		return diag.Errorf("unable to set resource instance `os` read value: %v", err)
	}
	if err := d.Set("ram", instance.RAM); err != nil {
		return diag.Errorf("unable to set resource instance `ram` read value: %v", err)
	}
	if err := d.Set("disk", instance.Disk); err != nil {
		return diag.Errorf("unable to set resource instance `disk` read value: %v", err)
	}
	if err := d.Set("main_ip", instance.MainIP); err != nil {
		return diag.Errorf("unable to set resource instance `main_ip` read value: %v", err)
	}
	if err := d.Set("vcpu_count", instance.VCPUCount); err != nil {
		return diag.Errorf("unable to set resource instance `vcpu_count` read value: %v", err)
	}
	if err := d.Set("date_created", instance.DateCreated); err != nil {
		return diag.Errorf("unable to set resource instance `date_created` read value: %v", err)
	}
	if err := d.Set("status", instance.Status); err != nil {
		return diag.Errorf("unable to set resource instance `status` read value: %v", err)
	}
	if err := d.Set("allowed_bandwidth", instance.AllowedBandwidth); err != nil {
		return diag.Errorf("unable to set resource instance `allowed_bandwidth` read value: %v", err)
	}
	if err := d.Set("netmask_v4", instance.NetmaskV4); err != nil {
		return diag.Errorf("unable to set resource instance `netmask_v4` read value: %v", err)
	}
	if err := d.Set("gateway_v4", instance.GatewayV4); err != nil {
		return diag.Errorf("unable to set resource instance `gateway_v4` read value: %v", err)
	}
	if err := d.Set("power_status", instance.PowerStatus); err != nil {
		return diag.Errorf("unable to set resource instance `power_status` read value: %v", err)
	}
	if err := d.Set("server_status", instance.ServerStatus); err != nil {
		return diag.Errorf("unable to set resource instance `server_status` read value: %v", err)
	}
	if err := d.Set("internal_ip", instance.InternalIP); err != nil {
		return diag.Errorf("unable to set resource instance `internal_ip` read value: %v", err)
	}
	if err := d.Set("kvm", instance.KVM); err != nil {
		return diag.Errorf("unable to set resource instance `kvm` read value: %v", err)
	}
	if err := d.Set("v6_network", instance.V6Network); err != nil {
		return diag.Errorf("unable to set resource instance `v6_network` read value: %v", err)
	}
	if err := d.Set("v6_main_ip", instance.V6MainIP); err != nil {
		return diag.Errorf("unable to set resource instance `v6_main_ip` read value: %v", err)
	}
	if err := d.Set("v6_network_size", instance.V6NetworkSize); err != nil {
		return diag.Errorf("unable to set resource instance `v6_network_size` read value: %v", err)
	}
	if err := d.Set("tags", instance.Tags); err != nil {
		return diag.Errorf("unable to set resource instance `tags` read value: %v", err)
	}
	if err := d.Set("firewall_group_id", instance.FirewallGroupID); err != nil {
		return diag.Errorf("unable to set resource instance `firewall_group_id` read value: %v", err)
	}
	if err := d.Set("region", instance.Region); err != nil {
		return diag.Errorf("unable to set resource instance `region` read value: %v", err)
	}
	if err := d.Set("plan", instance.Plan); err != nil {
		return diag.Errorf("unable to set resource instance `plan` read value: %v", err)
	}
	if err := d.Set("os_id", instance.OsID); err != nil {
		return diag.Errorf("unable to set resource instance `os_id` read value: %v", err)
	}
	if err := d.Set("app_id", instance.AppID); err != nil {
		return diag.Errorf("unable to set resource instance `app_id` read value: %v", err)
	}
	if err := d.Set("features", instance.Features); err != nil {
		return diag.Errorf("unable to set resource instance `features` read value: %v", err)
	}
	if err := d.Set("hostname", instance.Hostname); err != nil {
		return diag.Errorf("unable to set resource instance `hostname` read value: %v", err)
	}
	if err := d.Set("user_scheme", instance.UserScheme); err != nil {
		return diag.Errorf("unable to set resource instance `user_scheme` read value: %v", err)
	}

	backup, _, err := client.Instance.GetBackupSchedule(ctx, d.Id())
	if err != nil {
		return diag.Errorf("error getting backup schedule: %v", err)
	}

	if err := d.Set("backups", backupStatus(backup.Enabled)); err != nil {
		return diag.Errorf("unable to set resource instance `backups` read value: %v", err)
	}

	if backupStatus(backup.Enabled) != "disabled" {
		var bs []map[string]interface{}
		backupScheduleInfo := map[string]interface{}{
			"type": backup.Type,
			"hour": backup.Hour,
			"dom":  backup.Dom,
			"dow":  backup.Dow,
		}
		bs = append(bs, backupScheduleInfo)

		if err := d.Set("backups_schedule", bs); err != nil {
			return diag.Errorf("unable to set resource instance `backups_schedule` read value: %v", err)
		}
	} else {
		if err := d.Set("backups_schedule", nil); err != nil {
			return diag.Errorf("unable to set resource instance `backups_schedule` read value: %v", err)
		}
	}

	vpcs, err := getVPCs(client, d.Id())
	if err != nil {
		return diag.Errorf("%s", err.Error())
	}

	vpc2s, err := getVPC2s(client, d.Id())
	if err != nil {
		return diag.Errorf("%s", err.Error())
	}

	if _, vpcUpdate := d.GetOk("vpc_ids"); vpcUpdate {
		if err := d.Set("vpc_ids", vpcs); err != nil {
			return diag.Errorf("unable to set resource instance `vpc_ids` read value: %v", err)
		}
	}

	if _, vpc2Update := d.GetOk("vpc2_ids"); vpc2Update {
		if err := d.Set("vpc2_ids", vpc2s); err != nil {
			return diag.Errorf("unable to set resource instance `vpc2_ids` read value: %v", err)
		}
	}

	return nil
}

func resourceVultrInstanceUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*Client).govultrClient()

	req := &govultr.InstanceUpdateReq{
		Label:           d.Get("label").(string),
		FirewallGroupID: d.Get("firewall_group_id").(string),
		EnableIPv6:      govultr.BoolToBoolPtr(d.Get("enable_ipv6").(bool)),
	}

	if d.HasChange("plan") {
		log.Printf("[INFO] Updating Plan")
		_, newVal := d.GetChange("plan")
		plan := newVal.(string)
		req.Plan = plan
	}

	if d.HasChange("ddos_protection") {
		log.Printf("[INFO] Updating DDOS Protection")
		_, newVal := d.GetChange("ddos_protection")
		ddos := newVal.(bool)
		req.DDOSProtection = &ddos
	}

	bs, bsOK := d.GetOk("backups_schedule")
	_, newBackupValue := d.GetChange("backups")
	if d.HasChange("backups") {
		log.Printf("[INFO] Updating Backups")
		backups := newBackupValue.(string)
		req.Backups = backups

		if backups == "disabled" && bsOK {
			return diag.Errorf("Backups are being set to disabled please remove backups_schedule")
		} else if backups == "enabled" && !bsOK {
			return diag.Errorf("Backups are being set to enabled please add backups_schedule")
		}
	}

	if d.HasChange("vpc_ids") {
		log.Printf("[INFO] Updating vpc_ids")
		oldVPC, newVPC := d.GetChange("vpc_ids")

		var oldIDs []string
		for _, v := range oldVPC.([]interface{}) {
			oldIDs = append(oldIDs, v.(string))
		}

		var newIDs []string
		for _, v := range newVPC.([]interface{}) {
			newIDs = append(newIDs, v.(string))
		}

		req.AttachVPC = append(req.AttachVPC, diffSlice(oldIDs, newIDs)...)
		req.DetachVPC = append(req.DetachVPC, diffSlice(newIDs, oldIDs)...)
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

	if _, _, err := client.Instance.Update(ctx, d.Id(), req); err != nil {
		return diag.Errorf("error updating instance %s : %s", d.Id(), err.Error())
	}

	if d.HasChange("iso_id") {
		log.Printf("[INFO] Updating ISO")

		_, newISOId := d.GetChange("iso_id")
		if newISOId == "" {
			if _, err := client.Instance.DetachISO(ctx, d.Id()); err != nil {
				return diag.Errorf("error detaching iso from instance %s : %v", d.Id(), err)
			}
		} else {
			if _, err := client.Instance.AttachISO(ctx, d.Id(), newISOId.(string)); err != nil {
				return diag.Errorf("error attaching iso to instance %s : %v", d.Id(), err)
			}
		}
	}

	if newBackupValue.(string) == "enabled" && !bsOK {
		return diag.Errorf("Backups are being set to enabled please add backups_schedule")
	}

	// If we are disabling backups we don't do anything.
	// On the read that gets called we will nil out backups_schedule.
	if newBackupValue.(string) != "disabled" && d.HasChange("backups_schedule") {
		schedule := generateBackupSchedule(bs)
		if _, err := client.Instance.SetBackupSchedule(ctx, d.Id(), schedule); err != nil {
			return diag.Errorf("error setting backup for %s : %v", d.Id(), err)
		}
	}

	// There is a delay between the API data returning the newly updated plan change
	// This will wait until the plan has been updated before going to the read call
	if d.HasChange("plan") {
		oldP, newP := d.GetChange("plan")
		if _, err := waitForPlanUpgrade(ctx, d, newP.(string), []string{oldP.(string)}, meta); err != nil {
			return diag.Errorf("error while waiting for instance %s to have updated plan : %s", d.Id(), err)
		}
	}

	if d.HasChange("user_scheme") {
		log.Printf("[INFO] Updating UserScheme")
		_, newVal := d.GetChange("user_scheme")
		uScheme := newVal.(string)
		req.UserScheme = uScheme
	}

	return resourceVultrInstanceRead(ctx, d, meta)
}

func resourceVultrInstanceDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*Client).govultrClient()
	log.Printf("[INFO] Deleting instance (%s)", d.Id())

	if vpcIDs, vpcOK := d.GetOk("vpc_ids"); vpcOK {
		detach := &govultr.InstanceUpdateReq{}
		for _, v := range vpcIDs.([]interface{}) {
			detach.DetachVPC = append(detach.DetachVPC, v.(string))
		}

		if _, _, err := client.Instance.Update(ctx, d.Id(), detach); err != nil {
			return diag.Errorf("error detaching VPCs prior to deleting instance %s : %v", d.Id(), err)
		}
	}

	if vpcIDs, vpcOK := d.GetOk("vpc2_ids"); vpcOK {
		detach := &govultr.InstanceUpdateReq{}
		for _, v := range vpcIDs.([]interface{}) {
			detach.DetachVPC2 = append(detach.DetachVPC2, v.(string))
		}

		if _, _, err := client.Instance.Update(ctx, d.Id(), detach); err != nil {
			return diag.Errorf("error detaching VPC2s prior to deleting instance %s : %v", d.Id(), err)
		}
	}

	if _, isoOK := d.GetOk("iso_id"); isoOK {
		if _, err := client.Instance.DetachISO(ctx, d.Id()); err != nil {
			return diag.Errorf("error detaching ISO prior to deleting instance %s : %v", d.Id(), err)
		}
	}

	if err := client.Instance.Delete(ctx, d.Id()); err != nil {
		return diag.Errorf("error destroying instance %s : %v", d.Id(), err)
	}

	return nil
}

func optionCheck(options map[string]bool) (string, error) {
	var result []string
	for k, v := range options {
		if v {
			result = append(result, k)
		}
	}

	if len(result) > 1 {
		return "", fmt.Errorf("too many options have been selected : %v : please select one", result)
	}

	// Return back an empty slice so we can possibly add in osID
	if len(result) == 0 {
		return "", nil
	}

	return result[0], nil
}

func waitForServerAvailable(ctx context.Context, d *schema.ResourceData, target string, pending []string, attribute string, meta interface{}) (interface{}, error) { //nolint:lll
	log.Printf(
		"[INFO] Waiting for Server (%s) to have %s of %s",
		d.Id(), attribute, target)

	stateConf := &retry.StateChangeConf{
		Pending:        pending,
		Target:         []string{target},
		Refresh:        newServerStateRefresh(ctx, d, meta, attribute),
		Timeout:        60 * time.Minute,
		Delay:          10 * time.Second,
		MinTimeout:     3 * time.Second,
		NotFoundChecks: 60,
	}

	return stateConf.WaitForStateContext(ctx)
}

func newServerStateRefresh(ctx context.Context, d *schema.ResourceData, meta interface{}, attr string) retry.StateRefreshFunc { //nolint:lll
	client := meta.(*Client).govultrClient()
	return func() (interface{}, string, error) {
		log.Printf("[INFO] Creating Server")
		server, _, err := client.Instance.Get(ctx, d.Id())
		if err != nil {
			return nil, "", fmt.Errorf("error retrieving Server %s : %s", d.Id(), err)
		}

		if attr == "status" {
			log.Printf("[INFO] The Server Status is %s", server.Status)
			return server, server.Status, nil
		} else if attr == "power_status" {
			log.Printf("[INFO] The Server Power Status is %s", server.PowerStatus)
			return server, server.PowerStatus, nil
		} else {
			return nil, "", nil
		}
	}
}

func waitForPlanUpgrade(ctx context.Context, d *schema.ResourceData, target string, pending []string, meta interface{}) (interface{}, error) { //nolint:lll
	log.Printf(
		"[INFO] Waiting for instance (%s) to have plan of %s",
		d.Id(), target)

	stateConf := &retry.StateChangeConf{
		Pending:        pending,
		Target:         []string{target},
		Refresh:        newInstancePlanRefresh(ctx, d, meta),
		Timeout:        60 * time.Minute,
		Delay:          10 * time.Second,
		MinTimeout:     3 * time.Second,
		NotFoundChecks: 60,
	}

	return stateConf.WaitForStateContext(ctx)
}

func newInstancePlanRefresh(ctx context.Context, d *schema.ResourceData, meta interface{}) retry.StateRefreshFunc {
	client := meta.(*Client).govultrClient()
	return func() (interface{}, string, error) {
		log.Printf("[INFO] Upgrading instance")
		instance, _, err := client.Instance.Get(ctx, d.Id())
		if err != nil {
			return nil, "", fmt.Errorf("error retrieving instance %s : %s", d.Id(), err)
		}

		log.Printf("[INFO] The instances plan is %s", instance.Plan)
		return instance, instance.Plan, nil
	}
}

func generateBackupSchedule(backup interface{}) *govultr.BackupScheduleReq {
	k := backup.([]interface{})

	config := k[0].(map[string]interface{})
	return &govultr.BackupScheduleReq{
		Type: config["type"].(string),
		Hour: govultr.IntToIntPtr(config["hour"].(int)),
		Dom:  config["dom"].(int),
		Dow:  govultr.IntToIntPtr(config["dow"].(int)),
	}
}

func backupStatus(status *bool) string {
	if *status {
		return "enabled"
	} else {
		return "disabled"
	}
}

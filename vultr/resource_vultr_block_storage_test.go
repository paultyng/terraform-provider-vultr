package vultr

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccResourceVultrBlockStorage(t *testing.T) {
	rLabel := acctest.RandomWithPrefix("tf-bs-rs")
	rServerLabel := acctest.RandomWithPrefix("tf-vps-bs")
	rLabelUpdate := acctest.RandomWithPrefix("tf-test-update")

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCheckVultrBlockStorageDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccVultrBlockStorageConfig(rLabel, rServerLabel),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckVultrBlockStorageExists("vultr_block_storage.foo"),
					resource.TestCheckResourceAttr("vultr_block_storage.foo", "label", rLabel),
					resource.TestCheckResourceAttr("vultr_block_storage.foo", "size_gb", "10"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "region"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "date_created"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "cost"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "status"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "mount_id"),
				),
			},
			{
				Config: testAccVultrBlockStorageConfigAttach(rLabel, rServerLabel),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckVultrBlockStorageExists("vultr_block_storage.foo"),
					resource.TestCheckResourceAttr("vultr_block_storage.foo", "label", rLabel),
					resource.TestCheckResourceAttr("vultr_block_storage.foo", "size_gb", "10"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "region"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "date_created"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "cost"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "status"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "mount_id"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "attached_to_instance"),
				),
			},
			{
				Config: testAccVultrBlockStorageConfigUpdateLabel(rLabelUpdate, rServerLabel),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckVultrBlockStorageExists("vultr_block_storage.foo"),
					resource.TestCheckResourceAttr("vultr_block_storage.foo", "label", rLabelUpdate),
					resource.TestCheckResourceAttr("vultr_block_storage.foo", "size_gb", "10"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "region"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "date_created"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "cost"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "status"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "mount_id"),
				),
			},
			{
				Config: testAccVultrBlockStorageConfigResize(rLabelUpdate, rServerLabel),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckVultrBlockStorageExists("vultr_block_storage.foo"),
					//resource.TestCheckResourceAttr("vultr_block_storage.foo", "label", rLabelUpdate),
					resource.TestCheckResourceAttr("vultr_block_storage.foo", "size_gb", "15"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "region"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "date_created"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "cost"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "status"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "mount_id"),
				),
			},
			{
				// test detach by unsetting the attached_to_instance
				Config: testAccVultrBlockStorageConfigDetach(rLabelUpdate, rServerLabel),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckVultrBlockStorageExists("vultr_block_storage.foo"),
					//resource.TestCheckResourceAttr("vultr_block_storage.foo", "label", rLabelUpdate),
					resource.TestCheckResourceAttr("vultr_block_storage.foo", "size_gb", "15"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "region"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "date_created"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "cost"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "status"),
					resource.TestCheckResourceAttrSet("vultr_block_storage.foo", "mount_id"),
				),
			},
		},
	})
}

func testAccCheckVultrBlockStorageDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vultr_block_storage" {
			continue
		}

		bsID := rs.Primary.ID
		client := testAccProvider.Meta().(*Client).govultrClient()

		if _, err := client.BlockStorage.Get(context.Background(), bsID); err == nil {
			return fmt.Errorf("block storage still exists: %s", bsID)
		}

	}
	return nil
}

func testAccCheckVultrBlockStorageExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("Block storage ID is not set")
		}

		bsID := rs.Primary.ID
		client := testAccProvider.Meta().(*Client).govultrClient()

		if _, err := client.BlockStorage.Get(context.Background(), bsID); err != nil {
			return fmt.Errorf("Block storage does not exist: %s", bsID)
		}

		return nil
	}
}

func testAccVultrBlockStorageConfig(label, serverLabel string) string {
	return fmt.Sprintf(`
	resource "vultr_block_storage" "foo" {
		region  = "ewr"
		size_gb     = 10
		label       = "%s"
	  }

	    resource "vultr_instance" "ip" {
       label = "%s"
       region = "ewr"
       plan = "vc2-1c-1gb"
       os_id = 167
   }
  `, label, serverLabel)
}

func testAccVultrBlockStorageConfigAttach(label, serverLabel string) string {
	return fmt.Sprintf(`
	resource "vultr_block_storage" "foo" {
		region   = "ewr"
		size_gb     = 10
		label       = "%s"
		attached_to_instance = "${vultr_instance.ip.id}"
	  }

   resource "vultr_instance" "ip" {
       label = "%s"
       region = "ewr"
       plan = "vc2-1c-1gb"
       os_id = 167
   }
  `, label, serverLabel)
}

func testAccVultrBlockStorageConfigUpdateLabel(label, serverLabel string) string {
	return fmt.Sprintf(`
	resource "vultr_block_storage" "foo" {
		region   = "ewr"
		size_gb     = 10
		label       = "%s"
		attached_to_instance = "${vultr_instance.ip.id}"
	  }

   resource "vultr_instance" "ip" {
       label = "%s"
       region = "ewr"
       plan = "vc2-1c-1gb"
       os_id = 167
   }
  `, label, serverLabel)
}

func testAccVultrBlockStorageConfigResize(label, serverLabel string) string {
	return fmt.Sprintf(`
	resource "vultr_block_storage" "foo" {
		region   = "ewr"
		size_gb     = 15
		label       = "%s"
		attached_to_instance = "${vultr_instance.ip.id}"
	  }
   resource "vultr_instance" "ip" {
       label = "%s"
       region = "ewr"
       plan = "vc2-1c-1gb"
       os_id = 167
   }
  `, label, serverLabel)
}

func testAccVultrBlockStorageConfigDetach(label, serverLabel string) string {
	return fmt.Sprintf(`
	resource "vultr_block_storage" "foo" {
		region   = "ewr"
		size_gb     = 15
		label       = "%s"
	  }

   resource "vultr_instance" "ip" {
       label = "%s"
       region = "ewr"
       plan = "vc2-1c-1gb"
       os_id = 167
   }
  `, label, serverLabel)
}

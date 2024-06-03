package vultr

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccVultrContainerRegistry(t *testing.T) {
	crName := fmt.Sprintf("%s%d", "tfcr", rand.Int())

	name := "vultr_container_registry.foo"
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		CheckDestroy:      testAccCheckVultrContainerRegistryDestroy,
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccVultrContainerRegistryBase(crName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(name, "name", crName),
					resource.TestCheckResourceAttrSet(name, "plan"),
					resource.TestCheckResourceAttrSet(name, "region"),
					resource.TestCheckResourceAttrSet(name, "public"),
				),
			},
		},
	})
}

func testAccCheckVultrContainerRegistryDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vultr_container_registry" {
			continue
		}

		crID := rs.Primary.ID
		client := testAccProvider.Meta().(*Client).govultrClient()

		_, _, err := client.ContainerRegistry.Get(context.Background(), crID)
		if err == nil {
			return fmt.Errorf("container registry still exists: %s", crID)
		}
	}
	return nil
}

func testAccVultrContainerRegistryBase(name string) string {
	return fmt.Sprintf(`
		resource "vultr_container_registry" "foo" {
			name = "%s"
			region = "sjc"
			public = false 
			plan = "business"
		} `,
		name,
	)
}

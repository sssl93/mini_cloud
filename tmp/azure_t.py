from mini_cloud.compute.types import Provider
from mini_cloud.compute.providers import get_driver
from mini_cloud.compute.models import NodeAuthPassword

cls = get_driver(Provider.AZURE_ARM)
driver = cls(
    tenant_id='3c77bcc0-aaee-4a58-895b-7c433e28e79b',
    subscription_id='c83781b3-56bf-4dbf-bac4-1d03adc92307',
    cloud_environment='AzureChinaCloud',
    key='5f15c87b-6d90-4fc9-85f9-5d3a5f2c5eb5', secret='sG6TmtmTjz3+CBKtlvFmC4kVk9dmCRmv1ZabUW9M5Ho='
)


def list_nodes():
    x = driver.list_nodes()
    print(x)


def create_node():
    ima = driver.list_images(location=ObjMock('chinanorth'))[0]
    r = driver.create_node(name='libcloudtestvm1', size=ObjMock('Standard_A0'),
                           image=ima,
                           auth=NodeAuthPassword('Admin@123'), ex_resource_group='libcloud_test',
                           ex_storage_account='libcloudtest',
                           ex_blob_container='vhds',
                           ex_network='libcloud_test_network',
                           location=ObjMock('chinanorth'))
    print(r)


def list_sizes():
    r = driver.list_sizes(location=ObjMock('chinanorth'))
    print(r)


def list_locations():
    r = driver.list_locations()
    print(r)


def list_images():
    r = driver.list_images(location=ObjMock('chinanorth'))
    print(r)


def list_nodes():
    r = driver.list_nodes(ex_fetch_nic=False, ex_fetch_power_state=False, ex_resource_group='libcloud_test')
    print(r)


def destroy_node():
    node = driver.list_nodes(
        ex_fetch_nic=False, ex_fetch_power_state=False, ex_resource_group='libcloud_test')[0]
    r = driver.destroy_node(node, ex_destroy_nic=False, ex_destroy_vhd=False, )
    print(r)


def get_node():
    r = driver.ex_get_node('2bb658b90f561f824f14e701aa2d3484439986df')
    # r = driver.ex_get_node('/subscriptions/c83781b3-56bf-4dbf-bac4-1d03adc92307/resourceGroups/libcloud_test/providers/Microsoft.Compute/virtualMachines/libcloudtestvm1')
    print(r)


def list_resource_groups():
    r = driver.ex_list_resource_groups()
    print(r)


if __name__ == "__main__":
    list_locations()
    # list_sizes()
    # list_images()
    # create_node()
    # get_node()
    # list_nodes()
    # destroy_node()
    # list_resource_groups()

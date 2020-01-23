# -*- coding: utf-8 -*-
"""Interface between aws and escript"""

import traceback
from datetime import datetime, timedelta
from time import sleep

import boto.ec2
from boto.ec2.networkinterface import NetworkInterfaceCollection
from boto.ec2.networkinterface import NetworkInterfaceSpecification
from boto.ec2.blockdevicemapping import EBSBlockDeviceType
from boto.ec2.blockdevicemapping import BlockDeviceType
from boto.ec2.blockdevicemapping import BlockDeviceMapping
import boto.vpc
import boto.iam
from boto.ec2.elb import HealthCheck
from boto.ec2.elb.attributes import ConnectionDrainingAttribute
import boto3


class Aws(object):
    """Make a new Aws handle and return"""

    # http://aws.amazon.com/amazon-linux-ami/instance-type-matrix/
    ami_instance_map = \
        {
            'i386': {
                'paravirtual': {
                    'instance-store': ['m1.small', 'm1.medium',
                                       'c1.medium'],

                    'ebs': ['t1.micro',
                            't2.nano', 't2.micro', 't2.small', 't2.medium',
                            'm1.small', 'm1.medium',
                            'c1.medium',
                            'c3.large']
                }
            },

            'x86_64': {
                'paravirtual': {
                    'instance-store': ['m3.medium', 'm3.large', 'm3.xlarge', 'm3.2xlarge',
                                       'm1.small', 'm1.medium', 'm1.large', 'm1.xlarge',
                                       'c3.large', 'c3.xlarge', 'c3.2xlarge', 'c3.4xlarge', 'c3.8xlarge',
                                       'c1.medium', 'c1.xlarge',
                                       'm2.xlarge', 'm2.2xlarge', 'm2.4xlarge',
                                       'hi1.4xlarge',
                                       'hs1.8xlarge'],

                    'ebs': ['t1.micro',
                            'm3.medium', 'm3.large', 'm3.xlarge', 'm3.2xlarge',
                            'm1.small', 'm1.medium', 'm1.large', 'm1.xlarge',
                            'c3.large', 'c3.xlarge', 'c3.2xlarge', 'c3.4xlarge', 'c3.8xlarge',
                            'c1.medium', 'c1.xlarge',
                            'm2.xlarge', 'm2.2xlarge', 'm2.4xlarge',
                            'hi1.4xlarge',
                            'hs1.8xlarge']
                },

                'hvm': {
                    'instance-store': ['m3.medium', 'm3.large', 'm3.xlarge', 'm3.2xlarge',
                                       'c3.large', 'c3.xlarge', 'c3.2xlarge', 'c3.4xlarge', 'c3.8xlarge',
                                       'cc2.8xlarge',
                                       'hi1.4xlarge',
                                       'hs1.8xlarge',
                                       'i2.xlarge', 'i2.2xlarge', 'i2.4xlarge', 'i2.8xlarge',
                                       'r3.large', 'r3.xlarge', 'r3.2xlarge', 'r3.4xlarge', 'r3.8xlarge',
                                       'd2.xlarge', 'd2.2xlarge', 'd2.4xlarge', 'd2.8xlarge'],

                    'ebs': ['t2.nano', 't2.micro', 't2.small', 't2.medium', 't2.large',
                            'm3.medium', 'm3.large', 'm3.xlarge', 'm3.2xlarge',
                            'm4.large', 'm4.xlarge', 'm4.2xlarge', 'm4.4xlarge', 'm4.10xlarge',
                            'c3.large', 'c3.xlarge', 'c3.2xlarge', 'c3.4xlarge', 'c3.8xlarge',
                            'c4.large', 'c4.xlarge', 'c4.2xlarge', 'c4.4xlarge', 'c4.8xlarge',
                            'cc1.4xlarge',
                            'cc2.8xlarge',
                            'g2.2xlarge', 'g2.8xlarge',
                            'cg1.4xlarge',
                            'r3.large', 'r3.xlarge', 'r3.2xlarge', 'r3.4xlarge', 'r3.8xlarge',
                            'cr1.8xlarge',
                            'd2.xlarge', 'd2.2xlarge', 'd2.4xlarge', 'd2.8xlarge',
                            'i2.xlarge', 'i2.2xlarge', 'i2.4xlarge', 'i2.8xlarge',
                            'hi1.4xlarge',
                            'hs1.8xlarge']
                }
            }
        }

    # http://docs.aws.amazon.com/general/latest/gr/rande.html
    # only EC2
    region_code_map = {
            "us-east-1": "US East (Northern Virginia)",
            "us-west-2": "US West (Oregon)",
            "us-west-1": "US West (Northern California)",
            "eu-west-1": "EU (Ireland)",
            "eu-central-1": "EU (Frankfurt)",
            "ap-southeast-1": "Asia Pacific (Singapore)",
            "ap-southeast-2": "Asia Pacific (Sydney)",
            "ap-northeast-1": "Asia Pacific (Tokyo)",
            "ap-northeast-2": "Asia Pacific (Seoul)",
            "sa-east-1": "South America (Sao Paulo)",
            "us-gov-west-1": "GovCloud (US)",
            "ap-south-1": "Asia Pacific (Mumbai)",
            }

    error_message_map = {
        "not authorized": "Provided settings don't have sufficient permissions for AWS EC2.",
        "validate the provided access credentials": "Provided credentials are incorrect.",
        "request has expired": "Time of the machine is incorrect",
        "certificate verify failed": "AWS don't have a valid SSL certificate",
        "failure in name resolution": "Internet/DNS is not working",
        "check your aws secret access key": "Provided AWS secret access key is incorrect"
    }

    def __init__(self, region_name, aws_access_key_id, aws_secret_access_key):
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.conn = boto.ec2.connect_to_region(region_name, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        self.vpc_conn = boto.vpc.connect_to_region(region_name, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        self.iam_conn = boto.iam.connect_to_region(region_name, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        self.elb_conn = boto.ec2.elb.connect_to_region(region_name, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    def get_ec2_region_list(self):
        return self.region_code_map.items()

    def get_all_ec2_classic_security_groups(self):
        sl = self.conn.get_all_security_groups()
        return [(s.id, s.name, s.vpc_id) for s in sl if s.vpc_id is None]

    def get_all_security_groups_for_vpc(self, vpc_id):
        sl = self.conn.get_all_security_groups(filters={'vpc-id': vpc_id})
        return [(s.id, s.name, s.vpc_id) for s in sl]

    def get_all_iam_roles(self):
        rl = self.iam_conn.list_roles()
        return [r['role_name'] for r in rl['list_roles_response']['list_roles_result']['roles']]

    def get_all_key_pairs(self):
        kl = self.conn.get_all_key_pairs()
        return [k.name for k in kl]

    def get_all_vpcs(self):
        vl = self.vpc_conn.get_all_vpcs()
        return [(v.id, v.cidr_block, v.tags['Name'] if 'Name' in v.tags.keys() else '') for v in vl]

    def get_all_subnets(self):
        sl = self.vpc_conn.get_all_subnets()
        return [(s.id, s.cidr_block, s.tags['Name'] if 'Name' in s.tags.keys() else '', s.region.name) for s in sl]

    def get_all_running_instances(self):
        return self.conn.get_only_instances()

    def get_all_volumes(self):
        return self.conn.get_all_volumes()

    def get_my_snapshots(self):
        return self.conn.get_all_snapshots(owner='self')

    def get_all_subnets_for_vpc(self, vpc_id):
        sl = self.vpc_conn.get_all_subnets(filters={'vpc-id': vpc_id})
        return [(s.id, s.cidr_block, s.tags['Name'] if 'Name' in s.tags.keys() else '', s.region.name) for s in sl]

    def get_default_linux_storage_settings(self):
        return {'type': 'Root', 'Device': '/dev/sda1', 'Size': 8, 'delete_on_termination': True}

    def get_linux_device_type_list(self):
        return ['/dev/sdb', '/dev/sdc', '/dev/sdd', '/dev/sde', '/dev/sdf', '/dev/sdg', '/dev/sdh', '/dev/sdi', '/dev/sdj', '/dev/sdk', '/dev/sdl']

    def get_instance_type(self, ami_id):
        try:
            al = self.conn.get_all_images(filters={'image-id': ami_id})
            a = al[0]
            return self.ami_instance_map[a.architecture][a.virtualization_type][a.root_device_type]
        except IndexError:
            return []
        except KeyError:
            return []

    def get_all_instances(self, instance_ids=None):
        reservations = self.conn.get_all_reservations(instance_ids)
        instance_list = []
        for reservation in reservations:
            for i in reservation.instances:
                region = i.region.name
                cloudwatch = boto3.client("cloudwatch", region_name=region, aws_access_key_id=self.aws_access_key_id, aws_secret_access_key=self.aws_secret_access_key)
                today = datetime.now() + timedelta(days=1)  # today + 1 because we want all of today
                two_weeks = timedelta(days=14)
                start_date = today - two_weeks
                results = cloudwatch.get_metric_statistics(
                    Namespace='AWS/EC2',
                    MetricName='CPUUtilization',
                    Dimensions=[{'Name': 'InstanceId', 'Value': i.id}],
                    StartTime=start_date,
                    EndTime=today,
                    Period=3000,
                    Statistics=['Average'])
                # For some instances Datapoints is empty array, so catching exception
                try:
                    cpu_utilization = results['Datapoints'][0]['Average']
                except:
                    cpu_utilization = -1

                instance_list.append({
                    'instance_id': i.id,
                    'image_id': i.image_id,
                    'instance_type': i.instance_type,
                    'public_dns_name': i.public_dns_name,
                    'public_ip_address': i.ip_address,
                    'private_dns_name': i.private_dns_name,
                    'private_ip_address': i.private_ip_address,
                    'placement': i.placement,
                    'state': i.state,
                    'region': i.region.name,
                    'launch_time': i.launch_time,
                    'root_device_type': i.root_device_type,
                    'cpu_utilization': cpu_utilization,
                    'instance_name': i.tags['Name'] if 'Name' in i.tags.keys() else ''
                    })
        return instance_list

    def get_instance_details(self, instance_id):
        reservations = self.conn.get_all_instances(filters={'instance-id': instance_id})

        if len(reservations) > 0 and len(reservations[0].instances) > 0:
            i = reservations[0].instances[0]
        else:
            raise Exception("No such instance exists")

        return {
            'instance_id': i.id,
            'image_id': i.image_id,
            'instance_type': i.instance_type,
            'public_dns_name': i.public_dns_name,
            'public_ip_address': i.ip_address,
            'private_dns_name': i.private_dns_name,
            'private_ip_address': i.private_ip_address,
            'placement': i.placement,
            'state': i.state,
            'region': i.region.name,
            'launch_time': i.launch_time,
            'root_device_type': i.root_device_type,
            'instance_name': i.tags['Name'] if 'Name' in i.tags.keys() else ''
        }

    def add_or_update_vm_tags(self, instance_id, tag_list):
        """
        Update vm tags
        Args:
            instance_id (str): instance id of the aws image
            tag_list (list): list of dict of kv pairs
        Returns:
            None
        Raises:
            Exception if vm does not exist
        """
        reservations = self.conn.get_all_instances(filters={'instance-id': instance_id})
        try:
            instance_obj = reservations[0].instances[0]
        except Exception:
            raise Exception("Error getting vm with instance id %s" % instance_id)

        tags_dict = {}
        for tag in tag_list:
            tags_dict[tag['key']] = tag['value']
        instance_obj.add_tags(tags_dict)

    def get_instance_details_by_reservation_id(self, reservation_id):
        ctr = 1
        while ctr < 10:
            try:
                res_list = self.conn.get_all_instances(filters={'reservation-id': reservation_id})
                break
            except boto.exception.EC2ResponseError as e:
                if e.code == 'InvalidInstanceID.NotFound':
                    sleep(2**ctr)
                    ctr += 1
                else:
                    raise e

        if res_list:
            res = res_list[0]  # we always spin one vm at a time.
            ins_list = res.instances
            ins = ins_list[0]
            instance_name = ins.tags['Name'] if 'Name' in ins.tags.keys() else ''
            return {'id': ins.id, 'image_id': ins.image_id, 'instance_type': ins.instance_type,
'public_dns_name': ins.public_dns_name, 'public_ip_address': ins.ip_address, 'private_dns_name': ins.private_dns_name, 'private_ip_address': ins.private_ip_address, 'placement': ins.placement, 'state': ins.state, 'instance_name': instance_name, 'region': ins.region.name, 'launch_time': ins.launch_time, 'root_device_type': ins.root_device_type}
        else:
            return {}

    def get_instance_console_output(self, instance_id):
        res_list = self.conn.get_all_reservations(instance_ids=[instance_id])
        if res_list:
            res = res_list[0]  # we always spin one vm at a time.
            ins_list = res.instances
            ins = ins_list[0]
            cout = ins.get_console_output()
            return cout.output
        return None

    def terminate_instance(self, instance_id):
        instance_list = self.get_all_instances()
        for instance in instance_list:
            if instance['instance_id'] == instance_id and instance['state'] != 'terminated':
                return self.conn.terminate_instances(instance_ids=[instance_id])
        return None

    def start_instance(self, instance_id):
        try:
            return self.conn.start_instances(instance_ids=[instance_id])
        except boto.exception.EC2ResponseError as e:
            raise Exception(e.message)

    def stop_instance(self, instance_id):
        try:
            return self.conn.stop_instances(instance_ids=[instance_id])
        except boto.exception.EC2ResponseError as e:
            raise Exception(e.message)

    def reboot_instance(self, instance_id):
        try:
            return self.conn.reboot_instances(instance_ids=[instance_id])
        except boto.exception.EC2ResponseError as e:
            raise Exception(e.message)

    def get_ami_owned_by_me(self):
        al = self.conn.get_all_images(owners='self', filters={'image-type': 'machine', 'state': 'available'})
        return [(a.id, a.name, a.architecture, a.hypervisor, a.platform, a.virtualization_type, a.root_device_type, a.description) for a in al]

    def get_ami_executable_by_me(self):
        al = self.conn.get_all_images(executable_by='self', filters={'image-type': 'machine', 'state': 'available'})
        return [(a.id, a.name, a.architecture, a.hypervisor, a.platform, a.virtualization_type, a.root_device_type, a.description) for a in al]

    def get_ami_filter_by(self, filter_name, filter_value):
        wild_string = '*' + filter_value + '*'
        al = self.conn.get_all_images(filters={'image-type': 'machine', filter_name: wild_string})
        return [(a.id, a.name, a.architecture, a.hypervisor, a.platform, a.virtualization_type, a.root_device_type, a.description) for a in al]

    def get_ami_filter_by_name(self, name='', limit=None):
        return self.get_ami_filter_by('name', name)[0:limit]

    def get_ami_filter_by_ami_id(self, ami_id, limit=None):
        return self.get_ami_filter_by('image-id', ami_id)[0:limit]

    def get_ami_filter_by_description(self, description, limit=None):
        return self.get_ami_filter_by('description', description)[0:limit]

    def get_all_eips(self):
        eip_obj_list = []
        try:
            eip_obj_list = self.conn.get_all_addresses()
        except boto.exception.EC2ResponseError as e:
            raise Exception(e.message)

        def format_data(eip):
            return {
                'public_ip': eip.public_ip,
                'instance_id': eip.instance_id,
                'domain': eip.domain,
                'allocation_id': eip.allocation_id,
                'association_id': eip.association_id,
                'network_interface_id': eip.network_interface_id,
                'network_interface_owner_id': eip.network_interface_owner_id,
                'private_ip_address': eip.private_ip_address,
            }

        eip_data = map(format_data, eip_obj_list)
        return eip_data

    def get_all_free_eips(self, eip_type):
        eip_obj_list = []
        try:
            eip_obj_list = self.conn.get_all_addresses()
        except boto.exception.EC2ResponseError as e:
            raise Exception(e.message)

        free_eip_obj_list = []
        for item in eip_obj_list:
            if not item.instance_id and item.domain == eip_type:
                free_eip_obj_list.append(item)

        def format_data(eip):
            return {
                'public_ip': eip.public_ip,
                'instance_id': eip.instance_id,
                'domain': eip.domain,
                'allocation_id': eip.allocation_id,
                'association_id': eip.association_id,
                'network_interface_id': eip.network_interface_id,
                'network_interface_owner_id': eip.network_interface_owner_id,
                'private_ip_address': eip.private_ip_address,
            }

        eip_data = map(format_data, free_eip_obj_list)
        return eip_data

    def get_all_free_eip_public_ips(self, eip_type):
        eip_obj_list = []
        try:
            eip_obj_list = self.conn.get_all_addresses()
        except boto.exception.EC2ResponseError as e:
            raise Exception(e.message)

        free_eip_obj_list = []
        for item in eip_obj_list:
            if not item.instance_id and item.domain == eip_type:
                free_eip_obj_list.append(item)

        free_public_ips = [eip.public_ip for eip in free_eip_obj_list]
        return free_public_ips

    def associate_eip_with_instance(self, instance_id, public_ip=None, allocation_id=None,
                                    network_interface_id=None, private_ip_address=None,
                                    allow_reassociation=False):
        try:
            address = self.conn.associate_address_object(instance_id=instance_id, public_ip=public_ip,
                                                         allocation_id=allocation_id,
                                                         network_interface_id=network_interface_id,
                                                         private_ip_address=private_ip_address,
                                                         allow_reassociation=allow_reassociation)

            def format_eip_data(eip):
                return {
                    'public_ip': eip.public_ip,
                    'instance_id': eip.instance_id,
                    'domain': eip.domain,
                    'allocation_id': eip.allocation_id,
                    'association_id': eip.association_id,
                    'network_interface_id': eip.network_interface_id,
                    'network_interface_owner_id': eip.network_interface_owner_id,
                    'private_ip_address': eip.private_ip_address,
                }

            return format_eip_data(address)

        except boto.exception.EC2ResponseError as e:
            print "Could not associate Elastic IP with instance due to error: %s" % (e)
            return False

    def dissociate_eip_from_instance(self, public_ip=None, association_id=None):
        try:
            return self.conn.disassociate_address(public_ip=public_ip, association_id=association_id)
        except boto.exception.EC2ResponseError as e:
            print "Could not dissassociate Elastic IP from instance due to error: %s", (e)
            return False

    def allocate_eip(self, eip_type):
        try:
            eip = self.conn.allocate_address(eip_type)
        except boto.exception.EC2ResponseError as e:
            raise e

        return {
            'public_ip': eip.public_ip,
            'instance_id': eip.instance_id,
            'domain': eip.domain,
            'allocation_id': eip.allocation_id,
            'association_id': eip.association_id,
            'network_interface_id': eip.network_interface_id,
            'network_interface_owner_id': eip.network_interface_owner_id,
            'private_ip_address': eip.private_ip_address,
        }

    def release_eip(self, public_ip=None, allocation_id=None):
        try:
            return self.conn.release_address(public_ip=public_ip, allocation_id=allocation_id)
        except boto.exception.EC2ResponseError as e:
            print "Could not release Elastic IP due to error: %s" % (e)
            return False

    def add_tags_to_reservation(self, res, tags):
        ins_list = res.instances
        ins = ins_list[0]
        for k, v in tags.iteritems():
            ctr = 1
            while ctr < 10:
                try:
                    # print '%s: ctr: %s' % (ins.id, ctr)
                    ins.add_tag(k, value=v)
                    # print '%s: break' % ins.id
                    break
                except boto.exception.EC2ResponseError as e:
                    # print '%s: exception: %s' % (ins.id, e)
                    if e.code == 'InvalidInstanceID.NotFound':
                        sleep(2**ctr)
                        ctr += 1
                    else:
                        raise e

    '''
    block_device_mapping = {'Root': {'Device': '/dev/sda1', 'Size': 50, 'delete_on_termination': True}, 'EBS': [{'Device': '/dev/sdb', 'Size': 250, 'delete_on_termination': True}, {'Device': '/dev/sdc', 'Size': 500, 'delete_on_termination': False}]}
    '''
    def run_instance(self, image_id, key_name=None, instance_type='m1.small', security_groups=None, instance_name=None, instance_initiated_shutdown_behavior='terminate', user_data=None, tags=None, subnet_id=None, associate_public_ip_address=False, iam_role=None, block_device_mapping=None, **kwargs):

        bdm = None
        if block_device_mapping:
            root_vol = block_device_mapping['Root']

            volume_type = root_vol.get('volume_type', "")
            if volume_type == "io1":
                dev_sda1 = BlockDeviceType(size=root_vol['Size'], delete_on_termination=root_vol['delete_on_termination'], volume_type=root_vol['volume_type'], iops=root_vol['iops'])
            else:
                dev_sda1 = BlockDeviceType(size=root_vol['Size'], delete_on_termination=root_vol['delete_on_termination'], volume_type=root_vol['volume_type'])

            bdm = BlockDeviceMapping()
            bdm[block_device_mapping['Root']['Device']] = dev_sda1

            for device in block_device_mapping['EBS']:
                volume_type = device.get('volume_type', "")
                if volume_type == "io1":
                    dev_ = EBSBlockDeviceType(size=device['Size'], delete_on_termination=device['delete_on_termination'], volume_type=device['volume_type'], iops=device['iops'])
                else:
                    dev_ = EBSBlockDeviceType(size=device['Size'], delete_on_termination=device['delete_on_termination'], volume_type=device['volume_type'])
                bdm[device['Device']] = dev_

        try:
            nic = None
            if subnet_id:  # VPC Subnet
                nis = NetworkInterfaceSpecification(subnet_id=subnet_id, groups=security_groups, associate_public_ip_address=associate_public_ip_address)
                nic = NetworkInterfaceCollection(nis)

                res = self.conn.run_instances(image_id, key_name=key_name, instance_type=instance_type, network_interfaces=nic, instance_initiated_shutdown_behavior=instance_initiated_shutdown_behavior, user_data=user_data, instance_profile_name=iam_role, block_device_map=bdm, **kwargs)
            else:  # EC2 Classic
                res = self.conn.run_instances(image_id, key_name=key_name, instance_type=instance_type, security_groups=security_groups, instance_initiated_shutdown_behavior=instance_initiated_shutdown_behavior, user_data=user_data, instance_profile_name=iam_role, block_device_map=bdm, **kwargs)

            if instance_name:
                self.add_tags_to_reservation(res, {'Name': instance_name})

            if tags:
                self.add_tags_to_reservation(res, tags)

            return res.id
        except boto.exception.EC2ResponseError as e:
            print 'aws_response=%s' % e.message
            return False
        except Exception as e:
            print 'aws_error=%s' % e.message
            return False

    @classmethod
    def get_custom_error(cls, error_message):
        for error, custom_error in cls.error_message_map.iteritems():
            if error in error_message.lower():
                return custom_error
        return error_message

    def get_all_elb_names(self):
        elb_objs = self.elb_conn.get_all_load_balancers()
        return [elb.name for elb in elb_objs]

    def get_all_elbs(self):
        elb_obj_list = self.elb_conn.get_all_load_balancers()

        # converting into a JSON serializable format
        def format_elb_data(elb):
            return {
                'name': elb.name,
                'listeners': ",".join(map(str, elb.listeners or [])),
                'health_check': str(elb.health_check),
                'policies': str(elb.policies),
                'public_dns_name': elb.dns_name,
                'instances': ",".join(map(str, [instance.id for instance in elb.instances])),
                'availability_zones': ",".join(map(str, elb.availability_zones or [])),
                'subnets': ",".join(map(str, elb.subnets or [])),
                'security_groups': ",".join(map(str, elb.security_groups or [])),
                'vpc_id': elb.vpc_id
            }
        elb_list = map(format_elb_data, elb_obj_list)
        return elb_list

    def get_all_elb_objs(self):
        return self.elb_conn.get_all_load_balancers()

    def create_elb(self, name, zones, **kwargs):

        new_elb = self.elb_conn.create_load_balancer(name=name, zones=zones, **kwargs)
        return new_elb

    def add_member_to_elb(self, load_balancer_name, instances):
        return self.elb_conn.register_instances(load_balancer_name, instances)

    def remove_member_from_elb(self, load_balancer_name, instances):
        return self.elb_conn.deregister_instances(load_balancer_name, instances)

    def get_elb_data_by_name(self, load_balancer_name):
        try:
            elb = self.elb_conn.get_all_load_balancers(load_balancer_name)
        except boto.exception.EC2ResponseError as e:
            print 'Could not connect to ELB {0} due to AWS error response {1}'.format(load_balancer_name, e)
            return False
        except Exception as e:
            print 'Could not get ELB {0} due to error {1}'.format(load_balancer_name, e)
            return False

        def format_data(elb):
            return {
                'name': elb.name,
                'listeners': ",".join(map(str, elb.listeners or [])),
                'health_check': str(elb.health_check),
                'policies': str(elb.policies),
                'public_dns_name': elb.dns_name,
                'instances': ",".join(map(str, [instance.id for instance in elb.instances])),
                'availability_zones': ",".join(map(str, elb.availability_zones or [])),
                'subnets': ",".join(map(str, elb.subnets or [])),
                'security_groups': ",".join(map(str, elb.security_groups or [])),
                'vpc_id': elb.vpc_id
            }
        elb_data = map(format_data, elb)

        return elb_data

    def get_elb_by_name(self, load_balancer_name):
        try:
            elb = self.elb_conn.get_all_load_balancers(load_balancer_name)
        except boto.exception.EC2ResponseError as e:
            raise e
        return elb

    def configure_elb_health_check(self, elb, protocol, port, path='/index.html', timeout=5,
                                   interval=30, unhealthy_threshold=2,
                                   healthy_threshold=2):
        target = None
        if protocol in ['HTTP', 'HTTPS']:
            target = "{}:{}/{}".format(protocol, port, path)
        else:
            target = "{}:{}".format(protocol, port)

        try:
            health_check = HealthCheck(interval=interval, target=target,
                                       healthy_threshold=healthy_threshold,
                                       timeout=timeout,
                                       unhealthy_threshold=unhealthy_threshold)

            elb.configure_health_check(health_check)
        except boto.exception.EC2ResponseError as e:
            print "HealthCheck config failed with AWS response: {0}".format(e)
            return False
        except Exception as e:
            print "HealthCheck config failed due to error: {0}".format(e)
            return False

        return elb

    def check_if_elb_name_is_unique(self, name):
        elb_name_list = self.get_all_elb_names()

        if name in elb_name_list:
            return False
        else:
            return True

    def delete_elb_by_name(self, name):
        return self.elb_conn.delete_load_balancer(name)

    def get_all_availability_zones(self):
        zones = self.conn.get_all_zones()
        return [zone.name for zone in zones]

    def upload_ssl_cerificate(self, cert_name, public_key, private_key, cert_chain=None, path=None):
        return self.iam_conn.upload_server_cert(cert_name, public_key, private_key, cert_chain, path)

    def get_all_server_certificates(self):
        cert_data_list = self.iam_conn.get_all_server_certs()
        cert_metadata_list = cert_data_list['list_server_certificates_response']['list_server_certificates_result']['server_certificate_metadata_list']
        cert_info_list = []

        for cert in cert_metadata_list:
            cert_info_dict = {}
            cert_info_dict['name'] = cert['server_certificate_name']
            cert_info_dict['ssl_certificate_id'] = cert['arn']
            cert_info_list.append(cert_info_dict)

        return cert_info_list

    def add_listeners(self, elb_name, listeners=None, complex_listeners=None):
        try:
            return self.elb_conn.create_load_balancer_listeners(elb_name, listeners=listeners, complex_listeners=complex_listeners)
        except boto.exception.EC2ResponseError as e:
            print 'aws error response message: =%s' % e
            return False
        except Exception as e:
            print 'could not add listeners due to error %s' % e
            return False

    def get_elb_member_ids(self, elb_obj):
        return [instance.id for instance in elb_obj.instances]

    def create_stickiness_policy(self, elb_name, stickiness_policy_list):
        try:
            for policy in stickiness_policy_list:
                if policy.get('stickiness_config_type') == 'load_balancer':
                    self.elb_conn.create_lb_cookie_stickiness_policy(policy.get('cookie_expiration_period', None), elb_name, policy.get('policy_name', 'load_balancer_stickiness_policy'))
                elif policy.get('stickiness_config_type') == 'app':
                    self.elb_conn.create_app_cookie_stickiness_policy(policy.get('cookie_name'), elb_name, policy.get('policy_name'))

                self.elb_conn.set_lb_policies_of_listener(elb_name, policy.get('load_balancer_port', None), policy.get('policy_name', None))

        except boto.exception.EC2ResponseError as e:
            print 'aws error response message: =%s' % e
            return False
        except Exception as e:
            print 'could not create stickiness policy due to error %s' % e
            return False

        return True

    def modify_elb_attribute(self, elb_name, attribute_settings):
        try:
            self.elb_conn.modify_lb_attribute(elb_name, 'crossZoneLoadBalancing', attribute_settings.get('cross_zone_load_balancing', True))
            cda = ConnectionDrainingAttribute(self.elb_conn)
            cda.enabled = attribute_settings.get('enable_connection_draining', True)
            cda.timeout = attribute_settings.get('connection_draining', '300')
            self.elb_conn.modify_lb_attribute(elb_name, 'connectionDraining', cda)
        except boto.exception.EC2ResponseError as e:
            print 'Could not modify ELB attributes due to AWS error response {0}'.format(e)
            return False
        except Exception as e:
            print 'Could not modify ELB attributes due to error {0}'.format(e)
            return False

        return True

    def create_security_group(self, name, description, inbound_rules=None,
                              vpc_id=None, outbound_rules=None):
        """create ec2/vpc security group with all inbound and outbound_rules
        :param name: name of security group
        :param description: description of security group
        :param vpc_id: if vpc_id is None, EC2 security group will be created, otherwise VPC sg
        :param inbound_rules: inbound_rules, list of dictionaries with keys- protocol, from_port,
                              to_port, cidr_ip, src_group_id
        :param outbound_rules: only applicable in VPC security group, same as inbound_rules
        """
        try:
            if not inbound_rules:
                inbound_rules = list()

            if not outbound_rules:
                outbound_rules = list()

            sg_obj = self.conn.create_security_group(name, description)

            for inbound_rule in inbound_rules:
                self.conn.authorize_security_group(
                    group_id=sg_obj.id,
                    ip_protocol=inbound_rule['protocol'],
                    from_port=inbound_rule['from_port'],
                    to_port=inbound_rule.get('to_port'),
                    cidr_ip=inbound_rule.get('cidr_ip', '0.0.0.0/0'),
                    src_security_group_group_id=inbound_rule.get('src_group_id', None))

            if vpc_id:
                for outbound_rule in outbound_rules:
                    self.conn.authorize_security_group_egress(
                        group_id=sg_obj.id,
                        ip_protocol=outbound_rule['protocol'],
                        from_port=outbound_rule['from_port'],
                        to_port=outbound_rule.get('to_port'),
                        cidr_ip=outbound_rule.get('cidr_ip', '0.0.0.0/0'),
                        src_security_group_group_id=outbound_rule.get('src_group_id', None))

        except KeyError as e:
            print "{0} is missing in some rule".format(e)
            return False

        except boto.exception.EC2ResponseError as e:
            print "AWS error while creating security group: {0}".format(e.message)
            return False

        except Exception as e:
            traceback.print_exc()
            print "Error while creating security group: {0}".format(e)
            return False
        else:
            return self._get_sg_dict(sg_obj)

    def delete_security_group(self, sg_id):
        """delete_security_group
        :param sg_id: id of sg
        """

        try:
            return self.conn.delete_security_group(group_id=sg_id)
        except boto.exception.EC2ResponseError as e:
            print "Error while deleting security group: {}".format(e.message)
            return False

    def get_security_group(self, sg_id):
        """get security group info, rules
        :param sg_id: id of sg
        """

        try:
            sg_obj = self.conn.get_all_security_groups(group_ids=[sg_id])[0]
            return self._get_sg_dict(sg_obj)
        except boto.exception.EC2ResponseError as e:
            print "AWS error while getting info of security group: {}".format(e.message)
            return False

    def update_security_group(self, sg_id, inbound_rules=None,
                              outbound_rules=None):
        """modify ec2/vpc security group with all inbound and outbound_rules
        :param sg_id: security group id
        :param inbound_rules: all rules to keep/add inbound
        :param outbound_rules: all rules to keep/add outbound
        """

        try:
            if not inbound_rules:
                inbound_rules = list()

            if not outbound_rules:
                outbound_rules = list()

            sg_obj = self.conn.get_all_security_groups(group_ids=[sg_id])[0]
            self._update_sg_inbound_rules(sg_obj, inbound_rules)
            if sg_obj.vpc_id:
                self._update_sg_outbound_rules(sg_obj, outbound_rules)

            return self._get_sg_dict(sg_obj)

        except boto.exception.EC2ResponseError as e:
            print "AWS error while modifing security group: {1}".format(e.message)
            return False

        except Exception as e:
            traceback.print_exc()
            print "Error while modifing security group: {0}".format(e)
            return False

        return True

    def _update_sg_inbound_rules(self, sg_obj, rules):
        """_update_sg_inbound_rules
        :param class `boto.ec2.securitygroup.SecurityGroup` sg: security group obj
        :param inbound_rules: list of dict of rules
        """
        existing_rules = [dict(cidr_ip=str(rule.grants[0]),
                               from_port=rule.from_port,
                               protocol=rule.ip_protocol,
                               to_port=rule.to_port) for rule in sg_obj.rules]

        rules_to_remove = [item for item in existing_rules if item not in rules]
        rules_to_add = [item for item in rules if item not in existing_rules]

        for rule in rules_to_remove:
            self.conn.revoke_security_group(group_id=sg_obj.id, **rule)

        for rule in rules_to_add:
            self.conn.authorize_security_group(group_id=sg_obj.id, **rule)

    def _update_sg_outbound_rules(self, sg, rules):
        """_update_sg_outbound_rules
        :param class `boto.ec2.securitygroup.SecurityGroup` sg: security group obj
        :param outbound_rules: list of dict of rules
        """
        existing_rules = [dict(cidr_ip=str(rule.grants[0]),
                               from_port=rule.from_port,
                               protocol=rule.ip_protocol,
                               to_port=rule.to_port) for rule in sg.rules_egress]

        rules_to_remove = [item for item in existing_rules if item not in rules]
        rules_to_add = [item for item in rules if item not in existing_rules]

        for rule in rules_to_remove:
            self.conn.revoke_security_group_egress(group_id=sg.id, **rule)

        for rule in rules_to_add:
            self.conn.authorize_security_group_egress(group_id=sg.id, **rule)

    def _get_sg_dict(self, sg_obj):
        """ return dict from sg object
        :param sg_obj: sg obj
        """
        inbound_rules = [
            {
                "protocol": rule.ip_protocol,
                "from_port": rule.from_port,
                "to_port": rule.to_port,
                "cidr_ip": str(rule.grants[0])
            }
            for rule in sg_obj.rules]

        outbound_rules = [
            {
                "protocol": rule.ip_protocol,
                "from_port": rule.from_port,
                "to_port": rule.to_port,
                "cidr_ip": str(rule.grants[0])
            }
            for rule in sg_obj.rules_egress]

        return {
            "id": sg_obj.id,
            "name": sg_obj.name,
            "inbound_rules": inbound_rules,
            "outbound_rules": outbound_rules
        }

    def create_vpc(self, cidr_block, instance_tenancy='default'):
        """create_vpc
        :param cidr_block: CIDR block
        :param instance_tenancy: dedicated/default; instances that run in VPC on hardware that's
                                 dedicated the customer
        """
        try:
            vpc = self.vpc_conn.create_vpc(cidr_block, instance_tenancy)
        except boto.exception.EC2ResponseError as e:
            print "AWS error while creating VPC: {0}".format(e.message)
            return False
        else:
            return self._get_vpc_dict(vpc)

    def delete_vpc(self, vpc_id):
        """delete vpc
        :param vpc_id: vpc id
        """
        try:
            return self.vpc_conn.delete_vpc(vpc_id)
        except boto.exception.EC2ResponseError as e:
            print "AWS error while deleting VPC: {0}".format(e.message)
            return False

    def get_vpc(self, vpc_id):
        """get vpc details
        :param vpc_id: vpc id
        """
        try:
            vpc = self.vpc_conn.get_all_vpcs(vpc_ids=[vpc_id])[0]
            return self._get_vpc_dict(vpc)
        except boto.exception.EC2ResponseError as e:
            print "AWS error while fetching details of VPC: {0}".format(e.message)
            return False

    def update_vpc(self, vpc_id, classic_link_enable=False):
        """update vpc
        :param vpc_id: vpc id
        :param classic_link_enabled: Indicates whether ClassicLink is enabled
        """
        try:
            vpc = self.vpc_conn.get_all_vpcs(vpc_ids=[vpc_id])[0]
            if classic_link_enable:
                vpc.enable_classic_link()
            else:
                vpc.disable_classic_link()
        except boto.exception.EC2ResponseError as e:
            print "AWS error while updating VPC: {0}".format(e.message)
            return False
        else:
            return self._get_vpc_dict(vpc)

    def _get_vpc_dict(self, vpc):
        """return dict from vpc object
        :param vpc_obj: vpc obj
        """
        return {
            "id": vpc.id,
            "state": vpc.state,
            "cidr_block": vpc.cidr_block,
            "instance_tenancy": vpc.instance_tenancy,
            "classic_link_enabled": vpc.classic_link_enabled,
            'tags': vpc.tags
        }
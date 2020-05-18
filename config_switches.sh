
#!/bin/bash

# Configure OVS switches

ovs-vsctl set Bridge s1 protocols=OpenFlow13
ovs-vsctl set Bridge s2 protocols=OpenFlow13
ovs-vsctl set Bridge s3 protocols=OpenFlow13
ovs-vsctl set Bridge s4 protocols=OpenFlow13
ovs-vsctl set Bridge s5 protocols=OpenFlow13

sudo ovs-vsctl add bridge s1 flow_tables 0=@switch1 -- --id=@switch1 create flow_table flow_limit=100
sudo ovs-vsctl add bridge s2 flow_tables 0=@switch2 -- --id=@switch2 create flow_table flow_limit=100
sudo ovs-vsctl add bridge s3 flow_tables 0=@switch3 -- --id=@switch3 create flow_table flow_limit=100
sudo ovs-vsctl add bridge s4 flow_tables 0=@switch4 -- --id=@switch4 create flow_table flow_limit=100
sudo ovs-vsctl add bridge s5 flow_tables 0=@switch5 -- --id=@switch5 create flow_table flow_limit=100
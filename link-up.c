#include <stddef.h>
#include "header.h"


#include "archcommon.h"
#include "archlinux.h"


static option_default _none_default[] = {
	{ NULL, NULL }
};
static conversion _none_conv[] = {
	{ "iface", "link", get_token, 3, (char * []){".", "0", ""} },
	{ "iface", "vlan_id0", get_token, 3, (char * []){".", "1", ""} },
	{ "iface", "iface0", get_token, 3, (char * []){":", "0", ""} },
	{ "vlan_id0", "vlan_id1", get_token, 3, (char * []){":", "0", ""} },
	{ "vlan_id1", "vlan_id", to_decimal, 1, (char * []){"10"} },
	{ NULL, NULL, NULL, 0, NULL }
};
static int _none_up(interface_defn *ifd, execfn *exec) {
{
  if (!execute("echo %iface% %iface0%", ifd, exec) && !ignore_failures) return 0;
}
{
  if (!execute("[[/sbin/ip link set %iface0% alias \"%description%\"]]", ifd, exec) && !ignore_failures) return 0;
}
return 1;
}
static int _none_down(interface_defn *ifd, execfn *exec) { return 0; }
static int _none_rename(interface_defn *ifd, execfn *exec) { return 0; }
static method methods[] = {
        {
                "none",
                _none_up, _none_down, _none_rename,
                _none_conv, _none_default,
        },
};

address_family addr_link_up = {
        "link_up",
        sizeof(methods)/sizeof(struct method),
        methods
};

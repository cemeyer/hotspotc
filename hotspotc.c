#include <sys/types.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

/* Boilerplate. If this grows, move it to a util.h or something. */
#define nelem(arr) (sizeof(arr) / sizeof(arr[0]))
#ifndef __DECONST
# define __DECONST(t, v) ((t)(intptr_t)(v))
#endif
#define EXPORT_SYM __attribute__((visibility("default")))
#define ASSERT(cond, ...) do {							\
	if ((intptr_t)(cond))							\
		break;								\
										\
	assert_fail(#cond, __func__, __FILE__, __LINE__, ##__VA_ARGS__, NULL);	\
} while (false)

#define startswith(haystack, needle) \
	(strncmp((haystack), (needle), strlen((needle))) == 0)
#define streq(s1, s2) (strcmp((s1), (s2)) == 0)

#ifndef __must_check
# define __must_check __attribute__((warn_unused_result))
#endif

#define GETSTR(prompt, arr) getstr(prompt, (arr), sizeof(arr))

static void __attribute__((noreturn)) __attribute__((format(printf, 5, 6)))
assert_fail(const char *an, const char *fn, const char *file, unsigned line,
    const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "ASSERTION `%s' FAILED", an);
	if (fmt) {
		fputs(": ", stderr);

		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}

	fprintf(stderr, " at %s() (%s:%u)\n", fn, file, line);
	exit(EX_SOFTWARE);
}

static int __must_check
getstr(const char *prompt, char *buf, size_t n)
{
	char *s;

	printf("%s", prompt);
	fflush(stdout);

	s = fgets(buf, n, stdin);
	if (s == NULL)
		return EPIPE;

	return 0;
}

/* if_nameindex indices of the WLAN and gateway devices. */
static unsigned	g_wlanidx,
		g_gwidx;
static uint32_t	g_ap_ip;
static char	g_ssid[1024],
		g_passwd[100],
		g_ipstr[100],
		g_wlan_nam[IF_NAMESIZE + 1],
		g_gw_nam[IF_NAMESIZE + 1],
		*g_runconf = "/tmp/xxx_hotspotc_run.conf";

static int __must_check
validate_ip_str(const char *saddr, uint32_t *addr_out)
{
	uint32_t addr;
	int rc;

	rc = inet_pton(AF_INET, saddr, &addr);
	ASSERT(rc >= 0);

	if (rc) {
		if (addr_out)
			*addr_out = addr;
		return 0;
	}
	return EINVAL;
}

static int __must_check
find_wlan(unsigned *idx_out, char *nam_out)
{
	char line[200], *inf;
	FILE *iwp;
	int error;

	errno = ENOMEM;
	iwp = popen("iwconfig 2>/dev/null", "re");
	if (iwp == NULL)
		return errno;

	error = ENOENT;
	while (fgets(line, sizeof(line), iwp)) {
		if (startswith(line, " "))
			continue;
		if (startswith(line, "mon."))
			continue;
		if (strstr(line, "IEEE 802.11") == NULL)
			continue;

		/*
		 * Pick the first non-monitor 802.11 device we find. Not
		 * perfect, but...
		 */
		inf = strtok(line, " ");
		ASSERT(inf, "Parsing or iwconfig issue: line='%s'", line);

		printf("Wifi interface found: %s\n", inf);
		*idx_out = if_nametoindex(inf);
		ASSERT(*idx_out, "if_nametoindex: %s", strerror(errno));
		strcpy(nam_out, inf);
		error = 0;
		break;
	}

	if (pclose(iwp) < 0)
		error = errno;

	return error;
}

static int __must_check
pick_gateway(unsigned wlan_idx, unsigned *idx_out, char *nam_out)
{
	char wlan_if[IF_NAMESIZE + 1] = { 0 },
	     gw_if[IF_NAMESIZE + 1] = { 0 },
	     choice[10] = { 0 },
	     *opts;
	struct if_nameindex *ifs, *it;
	int error, option;

	ifs = if_nameindex();
	ASSERT(ifs, "oom");

	ASSERT(if_indextoname(wlan_idx, wlan_if), "if_indextoname: %s",
	    strerror(errno));

	option = -1;
	while (option == -1) {
		puts("Options:");

		for (it = ifs; it->if_name; it++) {
			if (startswith(it->if_name, "mon."))
				continue;
			if (startswith(it->if_name, "lo"))
				continue;
			if (streq(it->if_name, wlan_if))
				continue;

			if (option == -1) {
				option = it->if_index;
				opts = it->if_name;
			} else
				option = -2;
			printf("%u. '%s'\n", it->if_index, it->if_name);
		}

		if (option == -1) {
			puts("No usable NICs found.");
			error = ENOENT;
			goto out;
		} else if (option != -2) {
			ASSERT(option >= 0);

			printf("Only one option (%d), using it.\n", option);

			*idx_out = (unsigned)option;
			strcpy(nam_out, opts);
			error = 0;
			goto out;
		}

		if (fgets(choice, sizeof(choice), stdin) == NULL) {
			error = EPIPE;
			goto out;
		}

		errno = 0;
		option = (int)strtol(choice, NULL, 10);
		if (errno) {
			error = errno;
			goto out;
		}

		if (if_indextoname(option, gw_if)) {
			error = 0;
			*idx_out = option;
			strcpy(nam_out, gw_if);
			goto out;
		}

		puts("No such option.");
		option = -1;
	}

out:
	if_freenameindex(ifs);
	return error;
}

static int __must_check
get_ap_ip(uint32_t *addr_out, char *ipstr_out)
{
	char ipline[80], *s;

	while (true) {
		puts("Enter an IP address for your ap [192.168.45.1]:");
		s = fgets(ipline, sizeof(ipline), stdin);
		if (s == NULL)
			return EPIPE;

		if (streq(ipline, "\n"))
			strcpy(ipline, "192.168.45.1");

		if (validate_ip_str(ipline, addr_out) == 0)
			break;
	}

	strcpy(ipstr_out, ipline);

	return 0;
}

static int __must_check
write_hostapd_conf(const char *fn)
{
	FILE *conf;

	conf = fopen(fn, "wb");
	if (conf == NULL)
		return errno;

	fprintf(conf,
	    "interface=%s\n"
	    /* driver to use, nl80211 works in most cases */
	    "driver=nl80211\n"
	    "ssid=%s\n"
	    /*
	     * Sets the mode of wifi, depends upon the devices you will be
	     * using. It can be a,b,g,n. Setting to g ensures backward
	     * compatiblity.
	     * */
	    "hw_mode=g\n"
	    "channel=6\n"
	    /* mac address filtering. 0 means "accept unless in deny list" */
	    "macaddr_acl=0\n"
	    /* 1 will disable the broadcasting of ssid */
	    "ignore_broadcast_ssid=0\n"
	    /*
	     * Authentication algorithm
	     * 1 - only open system authentication
	     * 2 - both open system authentication and shared key
	     *     authentication
	     */
	    "auth_algs=1\n"
	    /*
	     * Which wpa implementation to use
	     * 1 - wpa only
	     * 2 - wpa2 only
	     * 3 - both
	     */
	    "wpa=3\n"
	    "wpa_passphrase=%s\n"
	    "wpa_key_mgmt=WPA-PSK\n"
	    "wpa_pairwise=TKIP\n"
	    "rsn_pairwise=CCMP\n",

	    g_wlan_nam, g_ssid, g_passwd);

	if (fclose(conf))
		return errno;
	return 0;
}

static int __must_check
configure(void)
{
	int error;

	puts("Verifying interfaces");
	error = find_wlan(&g_wlanidx, g_wlan_nam);
	if (error) {
		fprintf(stderr, "Wireless interface could not be found: %s\n",
		    strerror(error));
		goto out;
	}

	puts("Verifying Internet connection");
	error = pick_gateway(g_wlanidx, &g_gwidx, g_gw_nam);
	if (error) {
		fprintf(stderr, "Gateway interface could not be found: %s\n",
		    strerror(error));
		goto out;
	}

	error = get_ap_ip(&g_ap_ip, g_ipstr);
	if (error)
		goto out;

	error = GETSTR("Enter SSID (arbitrary string):", g_ssid);
	if (error)
		goto out;

	error = GETSTR("Enter ?10 digit password:", g_passwd);
	if (error)
		goto out;

	puts("Writing temporary configuration file for hostapd.");
	error = write_hostapd_conf(g_runconf);
	if (error)
		goto out;

	/*
	 * XXX serialize config in the future.
	 *
	 * Schema-ish:
	 * {'wlan': wlan, 'inet':ppp, 'ip':IP, 'netmask':Netmask,
	 *  'SSID':SSID, 'password':password}
	 */
	error = 0;

out:
	return error;
}

static int __attribute__((format(printf, 1, 2)))
xsystem(const char *fmt, ...)
{
	char buf[1024] = { 0 };
	va_list ap;
	int rc;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);

	rc = system(buf);
	if (rc == -1)
		err(EX_SOFTWARE, "system(3)");

	return WEXITSTATUS(rc);
}

static void
stop(void)
{
	int rc;

	rc = xsystem("ifconfig %s down", g_wlan_nam);
	if (rc)
		fprintf(stderr, "ifconfig %s down: %d\n", g_wlan_nam, rc);

	rc = xsystem("ifconfig mon.%s down", g_wlan_nam);
	if (rc)
		fprintf(stderr, "ifconfig mon.%s down: %d\n", g_wlan_nam, rc);

	/* XXX: Write out PIDs to future state serialization format... */
	(void) xsystem("pkill hostapd");

	fprintf(stderr, "TODO, kill dnsmasq and iptables rules.\n");
}

static int __must_check
start(void)
{
	char dhcpl[80], dhcph[80], *s, unused[10];
	int rc;

	rc = xsystem("ifconfig %s up %s netmask 255.255.255.0", g_wlan_nam, g_ipstr);
	if (rc) {
		fprintf(stderr, "ifconfig: %d\n", rc);
		exit(EX_SOFTWARE);
	}

	(void) xsystem("pkill hostapd");

	printf("Add iptables rules manually:\n"
	       "1. iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\n"
	       "2. iptables -A FORWARD -i %s -o %s -j ACCEPT -m state --state RELATED,ESTABLISHED\n"
	       "3. iptables -A FORWARD -i %s -o %s -j ACCEPT\n"
	       "4. iptables -I INPUT -i %s -j ACCEPT\n"
	       "5. iptables -I OUTPUT -i %s -j ACCEPT\n",
	       g_gw_nam,
	       g_gw_nam, g_wlan_nam,
	       g_wlan_nam, g_gw_nam,
	       g_wlan_nam,
	       g_wlan_nam);

	ASSERT(GETSTR("Added?", unused) == 0);

	/* Hack. Use GW subnet, from .20 -> .100 */
	strcpy(dhcpl, g_ipstr);
	strcpy(dhcph, g_ipstr);

	s = strrchr(dhcpl, '.');
	ASSERT(s);

	strcpy(s + 1, "20");

	s = strrchr(dhcph, '.');
	ASSERT(s);

	strcpy(s + 1, "100");

	/*
	 * Doesn't work if dnsmasq is already running at all, even with the
	 * other one in interface-binding (vs hogging) mode. Oh well.
	 */
	rc = xsystem("dnsmasq --conf-file=/dev/null --dhcp-authoritative "
	    "--interface=%s --dhcp-range=%s,%s,255.255.255.0,4h "
	    "--bind-interfaces", g_wlan_nam, dhcpl, dhcph);
	if (rc) {
		fprintf(stderr, "dnsmasq: %d\n", rc);
		exit(EX_SOFTWARE);
	}

	sleep(1);

	/* XXX use proper tmpfiles in the future */
	rc = xsystem("hostapd -B \"%s\"", g_runconf);
	if (rc) {
		fprintf(stderr, "hostapd: %d\n", rc);
		stop();
		exit(EX_SOFTWARE);
	}

	return 0;
}

int
main(int argc, char **argv)
{
	int error;

	/*
	 * XXX Admin must:
	 *   * Enable ipv4 packet forwarding (sysctl net.ipv4.ip_forward=1)
	 *   * Enable iptables forwarding (iptables -P FORWARD ACCEPT)
	 */

	/* No args for now... */
	(void)argc;
	(void)argv;

	error = configure();
	if (error)
		goto out;

	/*
	 * Possibly required for some Ubuntu variant (Trusty)?
	 *
	 * $ nmcli nm wifi off
	 * $ rfkill unblock wlan
	 */

	error = start();
	if (error)
		goto out;

	if (atexit(stop)) {
		error = ENOMEM;
		goto out;
	}

	puts("Ctrl-c when finished...");
	while (true)
		sleep(100);

out:
	if (error)
		return EX_SOFTWARE;
	return EX_OK;
}

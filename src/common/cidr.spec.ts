import { intersectsIpv4Mapped, ipInAnyCidr, ipInCidr, parseCidr, parseIp } from "./cidr.js";

const range = (value: string) => {
  const parsed = parseCidr(value);
  if (!parsed) throw new Error(`fixture "${value}" should parse`);
  return parsed;
};

describe("cidr (CC-49 round-5 MEDIUM-1 trusted-proxy allow-list)", () => {
  it("parses IPv4, IPv6 and IPv4-mapped IPv6 to the same address space", () => {
    expect(Array.from(parseIp("127.0.0.1")!)).toEqual([127, 0, 0, 1]);
    // Node hands back ::ffff:127.0.0.1 on a dual-stack listener; it must be the same host.
    expect(Array.from(parseIp("::ffff:127.0.0.1")!)).toEqual([127, 0, 0, 1]);
    expect(parseIp("::1")).toHaveLength(16);
    expect(Array.from(parseIp("2001:db8::1")!.slice(0, 4))).toEqual([0x20, 0x01, 0x0d, 0xb8]);
    expect(parseIp("192.168.0.1%eth0")).not.toBeNull();
  });

  it("refuses anything that is not exactly one spelling of one address", () => {
    for (const bad of [
      "",
      "  ",
      "127.0.0",
      "127.0.0.1.1",
      "256.0.0.1",
      "010.0.0.1", // leading zero: could be read as octal by some parsers
      "0x7f.0.0.1",
      "+1.0.0.1",
      "127.0.0.-1",
      "not-an-ip",
      "2001:db8::1::2",
      "12345::1",
      "gggg::1",
      "1:2:3:4:5:6:7:8:9",
    ]) {
      expect([bad, parseIp(bad)]).toEqual([bad, null]);
    }
  });

  it("matches inside a prefix and not outside it", () => {
    const lan = range("192.168.1.0/24");
    expect(ipInCidr("192.168.1.7", lan)).toBe(true);
    expect(ipInCidr("192.168.1.255", lan)).toBe(true);
    expect(ipInCidr("192.168.2.7", lan)).toBe(false);

    // A non-byte-aligned prefix must mask bits, not bytes.
    const half = range("10.0.128.0/17");
    expect(ipInCidr("10.0.128.1", half)).toBe(true);
    expect(ipInCidr("10.0.255.254", half)).toBe(true);
    expect(ipInCidr("10.0.127.255", half)).toBe(false);

    expect(ipInCidr("0.0.0.0", range("0.0.0.0/0"))).toBe(true);
    expect(ipInCidr("203.0.113.9", range("0.0.0.0/0"))).toBe(true);
  });

  it("treats a bare literal as a full-length prefix", () => {
    expect(ipInCidr("127.0.0.1", range("127.0.0.1"))).toBe(true);
    expect(ipInCidr("127.0.0.2", range("127.0.0.1"))).toBe(false);
    // …and the mapped form of the same host still matches.
    expect(ipInCidr("::ffff:127.0.0.1", range("127.0.0.1"))).toBe(true);
  });

  it("matches IPv6 prefixes and never across families", () => {
    const v6 = range("2001:db8::/32");
    expect(ipInCidr("2001:db8:1234::5", v6)).toBe(true);
    expect(ipInCidr("2001:db9::5", v6)).toBe(false);
    expect(ipInCidr("127.0.0.1", v6)).toBe(false);
    expect(ipInCidr("::1", range("127.0.0.0/8"))).toBe(false);
  });

  it("is fail-closed: an unparseable candidate or range is never a member", () => {
    expect(ipInCidr("not-an-ip", range("0.0.0.0/0"))).toBe(false);
    expect(ipInCidr("", range("0.0.0.0/0"))).toBe(false);
    for (const bad of [
      "10.0.0.0/33",
      "10.0.0.0/-1",
      "10.0.0.0/x",
      "2001:db8::/129",
      "junk/8",
      "10.0.0.0/8/8",
    ]) {
      expect([bad, parseCidr(bad)]).toEqual([bad, null]);
    }
  });

  it("ipInAnyCidr matches nothing for an empty list", () => {
    expect(ipInAnyCidr("127.0.0.1", [])).toBe(false);
    expect(ipInAnyCidr("127.0.0.1", [range("10.0.0.0/8"), range("127.0.0.0/8")])).toBe(true);
  });

  it("flags IPv6 ranges that overlap the IPv4-mapped block (CC-49 round-6 LOW-3)", () => {
    // These parse and look like "trust the v4 peers too", but a dual-stack peer is normalised
    // to its 4-byte IPv4 form, so a 16-byte range can never contain one: configuring one is a
    // node that boots and then rejects every single request. Callers turn this into a boot
    // failure that names the fix.
    for (const covering of ["::ffff:0:0/96", "::ffff:0:0/64", "::/0", "::/1"]) {
      expect([covering, intersectsIpv4Mapped(range(covering))]).toEqual([covering, true]);
    }
    // Real IPv6 proxy ranges, loopback and every IPv4 range are untouched.
    for (const fine of ["2001:db8::/32", "::1/128", "fe80::/10", "127.0.0.0/8", "0.0.0.0/0"]) {
      expect([fine, intersectsIpv4Mapped(range(fine))]).toEqual([fine, false]);
    }
    // `::ffff:127.0.0.1` is parsed AS the IPv4 literal, so it is a usable declaration.
    expect(intersectsIpv4Mapped(range("::ffff:127.0.0.1"))).toBe(false);
  });
});

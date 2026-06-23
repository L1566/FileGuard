package risk

import (
	"net"
	"strings"
	"sync"
)

// IPClassifier IP 地址分类器，判断访问来源属于内网、国内还是境外
type IPClassifier struct {
	mu          sync.RWMutex
	trustedNets []*net.IPNet // 公司内网/可信 IP 段
	chinaNets   []*net.IPNet // 中国 IP 段（简化）
}

// NewIPClassifier 创建 IP 分类器，trustedCIDRs 为额外可信 IP 段（除私有 IP 外）
func NewIPClassifier(trustedCIDRs []string) *IPClassifier {
	c := &IPClassifier{}
	for _, cidr := range trustedCIDRs {
		if _, net, err := net.ParseCIDR(cidr); err == nil {
			c.trustedNets = append(c.trustedNets, net)
		}
	}
	// 内置中国主要 IP 段（简化版，覆盖常见 CN IP）
	c.chinaNets = defaultChinaCIDRs()
	return c
}

// Classify 分类 IP 并返回评分
// level: intranet(内网) / domestic(国内异地) / foreign(境外)
// score: 0 / 50 / 100
func (c *IPClassifier) Classify(ipStr string) (level string, score int) {
	// 清理端口号
	if idx := strings.LastIndex(ipStr, ":"); idx > 0 {
		ipStr = ipStr[:idx]
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "foreign", 100
	}

	// 优先检查私有 IP
	if isPrivateIP(ip) {
		return "intranet", 0
	}

	// 检查可信 IP 段
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, net := range c.trustedNets {
		if net.Contains(ip) {
			return "intranet", 0
		}
	}

	// 检查是否为中国 IP
	for _, net := range c.chinaNets {
		if net.Contains(ip) {
			return "domestic", 50
		}
	}

	return "foreign", 100
}

// isPrivateIP 判断是否为私有/内网地址
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// RFC 1918 私有地址
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
	for _, cidr := range privateBlocks {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// defaultChinaCIDRs 内置中国主要 IPv4 段
func defaultChinaCIDRs() []*net.IPNet {
	// 简化版覆盖中国主要 IP 段（非精确，用于演示）
	prefixes := []string{
		"1.0.0.0/8", "14.0.0.0/8", "27.0.0.0/8", "36.0.0.0/8",
		"39.0.0.0/8", "42.0.0.0/8", "49.0.0.0/8", "58.0.0.0/8",
		"59.0.0.0/8", "60.0.0.0/8", "61.0.0.0/8",
		"101.0.0.0/8", "103.0.0.0/8", "106.0.0.0/8",
		"110.0.0.0/8", "111.0.0.0/8", "112.0.0.0/8",
		"113.0.0.0/8", "114.0.0.0/8", "115.0.0.0/8",
		"116.0.0.0/8", "117.0.0.0/8", "118.0.0.0/8",
		"119.0.0.0/8", "120.0.0.0/8", "121.0.0.0/8",
		"122.0.0.0/8", "123.0.0.0/8", "124.0.0.0/8",
		"125.0.0.0/8", "175.0.0.0/8", "180.0.0.0/8",
		"182.0.0.0/8", "183.0.0.0/8",
		"202.0.0.0/8", "203.0.0.0/8",
		"210.0.0.0/8", "211.0.0.0/8",
		"218.0.0.0/8", "219.0.0.0/8",
		"220.0.0.0/8", "221.0.0.0/8", "222.0.0.0/8", "223.0.0.0/8",
	}
	nets := make([]*net.IPNet, 0, len(prefixes))
	for _, cidr := range prefixes {
		_, net, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, net)
		}
	}
	return nets
}

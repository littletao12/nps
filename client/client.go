package client

import (
	"bufio"
	"bytes"
	"encoding/json"
	"ehang.io/nps-mux"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/astaxie/beego/logs"
	"github.com/xtaci/kcp-go"

	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/config"
	"ehang.io/nps/lib/conn"
	"ehang.io/nps/lib/crypt"
)

type DNSRecord struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Content    string    `json:"content"`
	Proxiable  bool      `json:"proxiable"`
	Proxied    bool      `json:"proxied"`
	TTL        int       `json:"ttl"`
	Settings   struct{}  `json:"settings"`
	Meta       struct{}  `json:"meta"`
	Comment    *string   `json:"comment"`
	Tags       []string  `json:"tags"`
	CreatedOn  time.Time `json:"created_on"`
	ModifiedOn time.Time `json:"modified_on"`
}

type DNSResponse struct {
	Result     []DNSRecord `json:"result"`
	Success    bool        `json:"success"`
	Errors     []interface{} `json:"errors"`
	Messages   []interface{} `json:"messages"`
	ResultInfo struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		Count      int `json:"count"`
		TotalCount int `json:"total_count"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type TRPClient struct {
	svrAddr        string
	bridgeConnType string
	proxyUrl       string
	vKey           string
	p2pAddr        map[string]string
	tunnel         *nps_mux.Mux
	signal         *conn.Conn
	ticker         *time.Ticker
	cnf            *config.Config
	disconnectTime int
	once           sync.Once
	originalSvrAddr string // 原始服务器地址，用于DNS解析
}

//new client
func NewRPClient(svraddr string, vKey string, bridgeConnType string, proxyUrl string, cnf *config.Config, disconnectTime int) *TRPClient {
	return &TRPClient{
		svrAddr:        svraddr,
		originalSvrAddr: svraddr,
		p2pAddr:        make(map[string]string, 0),
		vKey:           vKey,
		bridgeConnType: bridgeConnType,
		proxyUrl:       proxyUrl,
		cnf:            cnf,
		disconnectTime: disconnectTime,
		once:           sync.Once{},
	}
}

// resolveDNS resolves the DNS for pvpv domains using the API
func (s *TRPClient) resolveDNS() (string, error) {
	// Check if the server address contains pvpv.bid
	if !strings.Contains(s.originalSvrAddr, "pvpv.bid") {
		return s.originalSvrAddr, nil
	}

	// Extract the domain name from the server address
	host := strings.Split(s.originalSvrAddr, ":")[0]

	// Build the API URL
	apiUrl := "https://cf-dns-manage.pvdddsscccddseeepv.bid/api/zones/6e4fd48d6b9eecef05e47dba5a443926/dns-records/search?name=" + host + "&type=AAAA&key=4ztk3rwt12233vzwu0ljrhib5ub"

	// Make the API request
	resp, err := http.Get(apiUrl)
	if err != nil {
		logs.Error("DNS resolution API request failed: %v", err)
		return s.originalSvrAddr, err
	}
	defer resp.Body.Close()

	// Parse the response
	var dnsResp DNSResponse
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		logs.Error("Failed to parse DNS response: %v", err)
		return s.originalSvrAddr, err
	}

	// Check if the request was successful
	if !dnsResp.Success || len(dnsResp.Result) == 0 {
		logs.Error("DNS resolution failed: no records found")
		return s.originalSvrAddr, nil
	}

	// Get the IP address from the first record
	ip := dnsResp.Result[0].Content
	port := strings.Split(s.originalSvrAddr, ":")[1]
	resolvedAddr := ip + ":" + port

	logs.Info("DNS resolved for %s: %s", s.originalSvrAddr, resolvedAddr)
	return resolvedAddr, nil
}

var NowStatus int
var CloseClient bool

//start
func (s *TRPClient) Start() {
	CloseClient = false
	useResolvedIP := false // 标记是否使用解析的IP
retry:
	if CloseClient {
		return
	}
	NowStatus = 0
	
	var targetAddr string
	if useResolvedIP {
		// 使用API解析的IP
		resolvedAddr, err := s.resolveDNS()
		if err != nil {
			logs.Warn("DNS resolution error, falling back to original address: %v", err)
			targetAddr = s.originalSvrAddr
		} else {
			targetAddr = resolvedAddr
			logs.Info("Attempting to connect using resolved IP: %s", targetAddr)
		}
	} else {
		// 使用原始域名
		targetAddr = s.originalSvrAddr
		logs.Info("Attempting to connect using original domain: %s", targetAddr)
	}
	
	c, err := NewConn(s.bridgeConnType, s.vKey, targetAddr, common.WORK_MAIN, s.proxyUrl)
	if err != nil {
		logs.Error("Connection failed, will reconnect in five seconds: %v", err)
		// 切换连接方式
		useResolvedIP = !useResolvedIP
		time.Sleep(time.Second * 5)
		goto retry
	}
	if c == nil {
		logs.Error("Error data from server, will reconnect in five seconds")
		// 切换连接方式
		useResolvedIP = !useResolvedIP
		time.Sleep(time.Second * 5)
		goto retry
	}
	
	s.svrAddr = targetAddr
	logs.Info("Successful connection with server %s", s.svrAddr)
	//monitor the connection
	go s.ping()
	s.signal = c
	//start a channel connection
	go s.newChan()
	//start health check if the it's open
	if s.cnf != nil && len(s.cnf.Healths) > 0 {
		go heathCheck(s.cnf.Healths, s.signal)
	}
	NowStatus = 1
	//msg connection, eg udp
	s.handleMain()
}

//handle main connection
func (s *TRPClient) handleMain() {
	for {
		flags, err := s.signal.ReadFlag()
		if err != nil {
			logs.Error("Accept server data error %s, end this service", err.Error())
			break
		}
		switch flags {
		case common.NEW_UDP_CONN:
			//read server udp addr and password
			if lAddr, err := s.signal.GetShortLenContent(); err != nil {
				logs.Warn(err)
				return
			} else if pwd, err := s.signal.GetShortLenContent(); err == nil {
				var localAddr string
				//The local port remains unchanged for a certain period of time
				if v, ok := s.p2pAddr[crypt.Md5(string(pwd)+strconv.Itoa(int(time.Now().Unix()/100)))]; !ok {
					tmpConn, err := common.GetLocalUdpAddr()
					if err != nil {
						logs.Error(err)
						return
					}
					localAddr = tmpConn.LocalAddr().String()
				} else {
					localAddr = v
				}
				go s.newUdpConn(localAddr, string(lAddr), string(pwd))
			}
		}
	}
	s.Close()
}

func (s *TRPClient) newUdpConn(localAddr, rAddr string, md5Password string) {
	var localConn net.PacketConn
	var err error
	var remoteAddress string
	if remoteAddress, localConn, err = handleP2PUdp(localAddr, rAddr, md5Password, common.WORK_P2P_PROVIDER); err != nil {
		logs.Error(err)
		return
	}
	l, err := kcp.ServeConn(nil, 150, 3, localConn)
	if err != nil {
		logs.Error(err)
		return
	}
	logs.Trace("start local p2p udp listen, local address", localConn.LocalAddr().String())
	for {
		udpTunnel, err := l.AcceptKCP()
		if err != nil {
			logs.Error(err)
			l.Close()
			return
		}
		if udpTunnel.RemoteAddr().String() == string(remoteAddress) {
			conn.SetUdpSession(udpTunnel)
			logs.Trace("successful connection with client ,address %s", udpTunnel.RemoteAddr().String())
			//read link info from remote
			conn.Accept(nps_mux.NewMux(udpTunnel, s.bridgeConnType, s.disconnectTime), func(c net.Conn) {
				go s.handleChan(c)
			})
			break
		}
	}
}

//pmux tunnel
func (s *TRPClient) newChan() {
	// 独立解析DNS，保持与原有功能一致
	resolvedAddr, err := s.resolveDNS()
	if err != nil {
		logs.Warn("DNS resolution error in newChan, using current address: %v", err)
		// 使用当前服务器地址作为备选
		resolvedAddr = s.svrAddr
	} else {
		logs.Info("Using resolved IP for channel connection: %s", resolvedAddr)
	}
	
	tunnel, err := NewConn(s.bridgeConnType, s.vKey, resolvedAddr, common.WORK_CHAN, s.proxyUrl)
	if err != nil {
		logs.Error("connect to ", resolvedAddr, "error:", err)
		return
	}
	s.tunnel = nps_mux.NewMux(tunnel.Conn, s.bridgeConnType, s.disconnectTime)
	for {
		src, err := s.tunnel.Accept()
		if err != nil {
			logs.Warn(err)
			s.Close()
			break
		}
		go s.handleChan(src)
	}
}

func (s *TRPClient) handleChan(src net.Conn) {
	lk, err := conn.NewConn(src).GetLinkInfo()
	if err != nil || lk == nil {
		src.Close()
		logs.Error("get connection info from server error ", err)
		return
	}
	//host for target processing
	lk.Host = common.FormatAddress(lk.Host)
	//if Conn type is http, read the request and log
	if lk.ConnType == "http" {
		if targetConn, err := net.DialTimeout(common.CONN_TCP, lk.Host, lk.Option.Timeout); err != nil {
			logs.Warn("connect to %s error %s", lk.Host, err.Error())
			src.Close()
		} else {
			srcConn := conn.GetConn(src, lk.Crypt, lk.Compress, nil, false)
			go func() {
				common.CopyBuffer(srcConn, targetConn)
				srcConn.Close()
				targetConn.Close()
			}()
			for {
				if r, err := http.ReadRequest(bufio.NewReader(srcConn)); err != nil {
					srcConn.Close()
					targetConn.Close()
					break
				} else {
					logs.Trace("http request, method %s, host %s, url %s, remote address %s", r.Method, r.Host, r.URL.Path, r.RemoteAddr)
					r.Write(targetConn)
				}
			}
		}
		return
	}
	if lk.ConnType == "udp5" {
		logs.Trace("new %s connection with the goal of %s, remote address:%s", lk.ConnType, lk.Host, lk.RemoteAddr)
		s.handleUdp(src)
	}
	//connect to target if conn type is tcp or udp
	if targetConn, err := net.DialTimeout(lk.ConnType, lk.Host, lk.Option.Timeout); err != nil {
		logs.Warn("connect to %s error %s", lk.Host, err.Error())
		src.Close()
	} else {
		logs.Trace("new %s connection with the goal of %s, remote address:%s", lk.ConnType, lk.Host, lk.RemoteAddr)
		conn.CopyWaitGroup(src, targetConn, lk.Crypt, lk.Compress, nil, nil, false, nil)
	}
}

func (s *TRPClient) handleUdp(serverConn net.Conn) {
	// bind a local udp port
	local, err := net.ListenUDP("udp", nil)
	defer serverConn.Close()
	if err != nil {
		logs.Error("bind local udp port error ", err.Error())
		return
	}
	defer local.Close()
	go func() {
		defer serverConn.Close()
		b := common.BufPoolUdp.Get().([]byte)
		defer common.BufPoolUdp.Put(b)
		for {
			n, raddr, err := local.ReadFrom(b)
			if err != nil {
				logs.Error("read data from remote server error", err.Error())
			}
			buf := bytes.Buffer{}
			dgram := common.NewUDPDatagram(common.NewUDPHeader(0, 0, common.ToSocksAddr(raddr)), b[:n])
			dgram.Write(&buf)
			b, err := conn.GetLenBytes(buf.Bytes())
			if err != nil {
				logs.Warn("get len bytes error", err.Error())
				continue
			}
			if _, err := serverConn.Write(b); err != nil {
				logs.Error("write data to remote  error", err.Error())
				return
			}
		}
	}()
	b := common.BufPoolUdp.Get().([]byte)
	defer common.BufPoolUdp.Put(b)
	for {
		n, err := serverConn.Read(b)
		if err != nil {
			logs.Error("read udp data from server error ", err.Error())
			return
		}

		udpData, err := common.ReadUDPDatagram(bytes.NewReader(b[:n]))
		if err != nil {
			logs.Error("unpack data error", err.Error())
			return
		}
		raddr, err := net.ResolveUDPAddr("udp", udpData.Header.Addr.String())
		if err != nil {
			logs.Error("build remote addr err", err.Error())
			continue // drop silently
		}
		_, err = local.WriteTo(udpData.Data, raddr)
		if err != nil {
			logs.Error("write data to remote ", raddr.String(), "error", err.Error())
			return
		}
	}
}

// Whether the monitor channel is closed
func (s *TRPClient) ping() {
	s.ticker = time.NewTicker(time.Second * 5)
loop:
	for {
		select {
		case <-s.ticker.C:
			if s.tunnel != nil && s.tunnel.IsClose {
				s.Close()
				break loop
			}
		}
	}
}

func (s *TRPClient) Close() {
	s.once.Do(s.closing)
}

func (s *TRPClient) closing() {
	CloseClient = true
	NowStatus = 0
	if s.tunnel != nil {
		_ = s.tunnel.Close()
	}
	if s.signal != nil {
		_ = s.signal.Close()
	}
	if s.ticker != nil {
		s.ticker.Stop()
	}
}

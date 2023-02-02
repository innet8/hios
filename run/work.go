package run

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/innet8/hios/pkg/logger"
	"github.com/innet8/hios/pkg/xrsa"
	"github.com/innet8/hios/version"
	"github.com/togettoyou/wsc"
	"io/ioutil"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	logDir   = "/usr/lib/hicloud/log"
	tmpDir   = "/usr/lib/hicloud/tmp"
	binDir   = "/usr/lib/hicloud/bin"
	sshDir   = "/usr/lib/hicloud/.ssh"
	workDir  = "/usr/lib/hicloud/work"
	startDir = "/usr/lib/hicloud/start"

	serverPublic string
	nodePublic   string
	nodePrivate  string

	connectRand string
	monitorRand string

	configUpdating bool
	configContinue string

	ws        *wsc.Wsc
	hostState *State

	costMap     = make(map[string]*costModel)
	manyipMap   = make(map[string]*manyipModel)
	monitorMap  = make(map[string]*monitorModel)
	transferMap = make(map[string]*Wireguard)
	speedMap    = make(map[string]*Wireguard)
	pingMinMap  = make(map[string]float64)
	dantedMap   = make(map[string]string)
	xrayMap     = make(map[string]string)
	daemonMap   = make(map[string]string)
)

type msgModel struct {
	Type    string    `json:"type"`
	Content string    `json:"content"`
	File    fileModel `json:"file"`
	Cmd     cmdModel  `json:"cmd"`
}

type fileModel struct {
	Type    string `json:"type"`
	Path    string `json:"path"`
	Before  string `json:"before"`
	After   string `json:"after"`
	Content string `json:"content"`
}

type cmdModel struct {
	Log      bool   `json:"log"`
	Callback string `json:"callback"`
	Content  string `json:"content"`
}

type sendModel struct {
	Type   string      `json:"type"`
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

type callModel struct {
	Callback string `json:"callback"`
	Output   string `json:"output"`
	Err      string `json:"err"`
}

type pingModel struct {
	Ip   string
	Xmt  float64
	Rcv  float64
	Loss float64
	Min  float64
	Avg  float64
	Max  float64
}

type costModel struct {
	Interface string
	Ip        string
	Cost      int
}

type manyipModel struct {
	Interface string
	Alias     string
	CurrentIp string
	ManyIp    string
}

type monitorModel struct {
	State string
	Ping  float64
	Unix  int64
}

// WorkStart Work开始
func WorkStart() {
	_ = logger.SetLogger(`{"File":{"filename":"/usr/lib/hicloud/log/work.log","level":"TRAC","daily":true,"maxlines":100000,"maxsize":10,"maxdays":3,"append":true,"permit":"0660"}}`)
	//
	if !Exists(fmt.Sprintf("%s/server_public", sshDir)) {
		logger.Error("[start] server public key does not exist")
		os.Exit(1)
	}
	if !Exists(fmt.Sprintf("%s/node_public", sshDir)) {
		logger.Error("[start] node public key does not exist")
		os.Exit(1)
	}
	if !Exists(fmt.Sprintf("%s/node_private", sshDir)) {
		logger.Error("[start] node private key does not exist")
		os.Exit(1)
	}
	serverPublic = ReadFile(fmt.Sprintf("%s/server_public", sshDir))
	nodePublic = ReadFile(fmt.Sprintf("%s/node_public", sshDir))
	nodePrivate = ReadFile(fmt.Sprintf("%s/node_private", sshDir))
	//
	origin := strings.Replace(os.Getenv("HI_URL"), "https://", "wss://", 1)
	origin = strings.Replace(origin, "http://", "ws://", 1)
	if strings.Count(origin, "/") > 2 {
		origins := strings.Split(origin, "/")
		origin = fmt.Sprintf("%s/%s/%s", origins[0], origins[1], origins[2])
	}
	nodeName, _ := os.Hostname()
	nonce := RandString(8)
	ts := time.Now().Unix()
	secret := os.Getenv("HI_TOKEN")
	token := StringMd5(fmt.Sprintf("nonce=%s&ts=%d&ver=%s%s", nonce, ts, version.Version, secret))
	wsUrl := fmt.Sprintf("%s/ws?action=hios&mode=%s&token=%s&name=%s&cid=%s&ver=%s&sha=%s&nonce=%s&ts=%d", origin, os.Getenv("HI_MODE"), token, nodeName, os.Getenv("HI_CID"), version.Version, version.CommitSHA, nonce, ts)
	//
	err := Mkdir(logDir, 0755)
	if err != nil {
		logger.Error(fmt.Sprintf("[start] failed to create log dir: %s\n", err.Error()))
		os.Exit(1)
	}
	startRun()
	//
	done := make(chan bool)
	ws = wsc.New(wsUrl)
	// 自定义配置
	ws.SetConfig(&wsc.Config{
		WriteWait:         10 * time.Second,
		MaxMessageSize:    512 * 1024, // 512KB
		MinRecTime:        2 * time.Second,
		MaxRecTime:        30 * time.Second,
		RecFactor:         1.5,
		MessageBufferSize: 1024,
	})
	// 设置回调处理
	ws.OnConnected(func() {
		logger.Debug("[ws] connected: ", ws.WebSocket.Url)
		logger.SetWebsocket(ws)
		onConnected()
	})
	ws.OnConnectError(func(err error) {
		logger.Debug("[ws] connect error: ", err.Error())
	})
	ws.OnDisconnected(func(err error) {
		logger.Debug("[ws] disconnected: ", err.Error())
	})
	ws.OnClose(func(code int, text string) {
		logger.Debug("[ws] close: ", code, text)
		done <- true
	})
	ws.OnTextMessageSent(func(message string) {
		if !strings.HasPrefix(message, "r:") {
			logger.Debug("[ws] text message sent: ", message)
		}
	})
	ws.OnBinaryMessageSent(func(data []byte) {
		logger.Debug("[ws] binary message sent: ", string(data))
	})
	ws.OnSentError(func(err error) {
		logger.Debug("[ws] sent error: ", err.Error())
	})
	ws.OnPingReceived(func(appData string) {
		logger.Debug("[ws] ping received: ", appData)
	})
	ws.OnPongReceived(func(appData string) {
		logger.Debug("[ws] pong received: ", appData)
	})
	ws.OnTextMessageReceived(func(message string) {
		if strings.HasPrefix(message, "r:") {
			message = xrsa.Decrypt(message[2:], nodePublic, nodePrivate) // 判断数据解密
		} else {
			logger.Debug("[ws] text message received: ", message)
		}
		handleMessageReceived(message)
	})
	ws.OnBinaryMessageReceived(func(data []byte) {
		logger.Debug("[ws] binary message received: ", string(data))
	})
	// 开始连接
	go ws.Connect()
	for {
		select {
		case <-done:
			return
		}
	}
}

// 连接成功
func onConnected() {
	connectRand = RandString(6)
	go func() {
		// 每10秒任务
		r := connectRand
		t := time.NewTicker(10 * time.Second)
		for {
			select {
			case <-t.C:
				if r != connectRand {
					logger.Debug("[timed] '%s' task A jump", r)
					return
				}
				timedTaskA()
			}
		}
	}()
	go func() {
		// 每50秒任务
		r := connectRand
		t := time.NewTicker(50 * time.Second)
		for {
			select {
			case <-t.C:
				if r != connectRand {
					logger.Debug("[timed] '%s' task B jump", r)
					return
				}
				timedTaskB()
			}
		}
	}()
}

// 启动运行
func startRun() {
	_ = os.RemoveAll(tmpDir)
	_ = os.MkdirAll(tmpDir, os.ModePerm)
	//
	_ = os.MkdirAll(workDir, os.ModePerm)
	_ = os.MkdirAll(startDir, os.ModePerm)
	path := fmt.Sprintf(startDir)
	files, err := filepath.Glob(filepath.Join(path, "*"))
	if err != nil {
		logger.Error("[start] error: %s", err)
	}
	for i := range files {
		file := files[i]
		content := ReadFile(file)
		_, _ = Cmd("-c", content)
	}
}

// 定时任务A（上报：系统状态、入口网速）
func timedTaskA() {
	hiMode := os.Getenv("HI_MODE")
	if hiMode == "host" {
		getState()
	} else if hiMode == "hihub" {
		getSpeed()
	}
}

// 定时任务B（上报：ping、流量统计）
func timedTaskB() {
	hiMode := os.Getenv("HI_MODE")
	if hiMode == "hihub" {
		// 公网 ping
		pingSend()
		// 对端 ping
		pingPPP()
		// 多IP ping
		go pingMany()
		// wg 流量统计
		getTransfer()
	}
}

// 主机状态
func getState() {
	hostState = GetHostState(hostState)
	if hostState == nil {
		return
	}
	value, err := json.Marshal(hostState)
	if err != nil {
		logger.Error("[state] host error: %s", err)
		return
	}
	sendMessage := formatSendMsg("state", string(value))
	_ = ws.SendTextMessage(sendMessage)
}

// wg网速计算
func getSpeed() {
	speedMap = GetWireguardTransfer(speedMap, false)
	if speedMap == nil {
		return
	}
	var array []string
	for _, speed := range speedMap {
		val, err := json.Marshal(speed)
		if err == nil {
			array = append(array, string(val))
		}
	}
	if len(array) == 0 {
		return
	}
	value, err := json.Marshal(array)
	if err != nil {
		return
	}
	sendMessage := formatSendMsg("speed", string(value))
	_ = ws.SendTextMessage(sendMessage)
}

// wg流量统计
func getTransfer() {
	transferMap = GetWireguardTransfer(transferMap, true)
	if transferMap == nil {
		return
	}
	var array []string
	for _, transfer := range transferMap {
		val, err := json.Marshal(transfer)
		if err == nil {
			array = append(array, string(val))
		}
	}
	if len(array) == 0 {
		return
	}
	value, err := json.Marshal(array)
	if err != nil {
		return
	}
	sendMessage := formatSendMsg("transfer", string(value))
	_ = ws.SendTextMessage(sendMessage)
}

// ping 对端并更新对端cost值
func pingPPP() {
	pppFile := fmt.Sprintf("%s/pppip", workDir)
	if !Exists(pppFile) {
		return
	}
	logger.Debug("[ppp] start ping")
	_, err := pingFile(pppFile, "")
	if err != nil {
		logger.Debug("[ppp] ping error: %s", err)
		return
	}
	costContent := ""
	for ip, model := range costMap {
		cost := int(math.Ceil(pingMinMap[ip]))
		if cost == 0 || cost > 9999 {
			cost = 9999
		}
		diff := math.Abs(float64(model.Cost - cost))
		update := false
		if cost <= 10 {
			update = diff >= 2 // ping值相差≥2
		} else if cost <= 100 {
			update = diff >= 5 // ping值相差≥5
		} else if cost <= 200 {
			update = diff >= 10 // ping值相差≥10
		} else {
			update = diff >= 20 // ping值相差≥20
		}
		if update {
			model.Cost = cost
			costMap[ip] = model
			costContent = fmt.Sprintf("%s\nset protocols ospf interface %s cost %d", costContent, model.Interface, model.Cost)
			logger.Info("[cost] change %s cost: %d", model.Interface, model.Cost)
		}
	}
	if len(costContent) == 0 {
		return
	}
	costFile := fmt.Sprintf("%s/cost", binDir)
	costContent = fmt.Sprintf("#!/bin/vbash\nsource /opt/vyatta/etc/functions/script-template\n%s\ncommit\nexit", costContent)
	err = ioutil.WriteFile(costFile, []byte(costContent), 0666)
	if err != nil {
		logger.Error("[cost] write file error: %s", err)
		return
	}
	_, _ = Cmd("-c", fmt.Sprintf("chmod +x %s", costFile))
	cmdRes, cmdErr := Command(costFile)
	if cmdErr != nil {
		logger.Error("[cost] set error: %s %s", cmdRes, cmdErr)
	} else {
		logger.Debug("[cost] set success")
	}
}

// ping 多ip并更新网卡地址
func pingMany() {
	logger.Debug("[manyip] start ping %d", len(manyipMap))
	var execArray []string
	var wait sync.WaitGroup
	var lock sync.Mutex
	for alias, model := range manyipMap {
		wait.Add(1)
		go func(alias string, model *manyipModel) {
			defer wait.Done()
			cmd := fmt.Sprintf("fping -A -u -q -4 -t 2000 -c 5 %s", model.ManyIp)
			output, err := Cmd("-c", cmd)
			if output == "" && err != nil {
				return
			}
			result, err := formatFping(output)
			if err != nil {
				return
			}
			newIp := ""
			newPing := float64(0)
			oldPing := float64(0)
			for ip, pingM := range result {
				if pingM.Min > 0 && (newPing == 0 || pingM.Min < newPing) {
					newIp = ip
					newPing = pingM.Min
				}
				if ip == model.CurrentIp {
					oldPing = pingM.Min
				}
			}
			if newIp != "" && model.CurrentIp != newIp {
				lock.Lock()
				model.CurrentIp = newIp
				manyipMap[alias] = model
				execArray = append(execArray, fmt.Sprintf("set interfaces wireguard %s peer %s address %s", model.Interface, model.Alias, newIp))
				logger.Info("[manyip] change %s %s address: %s(%v) => %s(%v)", model.Interface, model.Alias, model.CurrentIp, oldPing, newIp, newPing)
				lock.Unlock()
			}
		}(alias, model)
	}
	wait.Wait()
	if len(execArray) == 0 {
		return
	}
	manyipFile := fmt.Sprintf("%s/manyip", binDir)
	manyipContent := fmt.Sprintf("#!/bin/vbash\nsource /opt/vyatta/etc/functions/script-template\n%s\ncommit\nexit", strings.Join(execArray, "\n"))
	err := ioutil.WriteFile(manyipFile, []byte(manyipContent), 0666)
	if err != nil {
		logger.Error("[manyip] write file error: %s", err)
		return
	}
	_, _ = Cmd("-c", fmt.Sprintf("chmod +x %s", manyipFile))
	cmdRes, cmdErr := Command(manyipFile)
	if cmdErr != nil {
		logger.Error("[manyip] set error: %s %s", cmdRes, cmdErr)
	} else {
		logger.Debug("[manyip] set success")
	}
}

// ping 文件并发送
func pingSend() {
	fileName := fmt.Sprintf("%s/ips", workDir)
	if !Exists(fileName) {
		return
	}
	logger.Debug("[ping] start '%s'", fileName)
	result, err := pingFile(fileName, "")
	if err != nil {
		logger.Debug("[ping] error '%s': %s", fileName, err)
		return
	}
	sendMessage := formatSendMsg("ping", result)
	_ = ws.SendTextMessage(sendMessage)
}

// ping文件
func pingFile(path string, source string) (string, error) {
	result, err := pingFileMap(path, source, 2000, 5)
	if err != nil {
		return "", err
	}
	value, errJson := json.Marshal(result)
	return string(value), errJson
}

// 遍历ping文件内ip，并返回ping结果
func pingFileMap(path string, source string, timeout int, count int) (map[string]*pingModel, error) {
	cmd := fmt.Sprintf("fping -A -u -q -4 -t %d -c %d -f %s", timeout, count, path)
	if source != "" {
		cmd = fmt.Sprintf("fping -A -u -q -4 -S %s -t %d -c %d -f %s", source, timeout, count, path)
	}
	output, err := Cmd("-c", cmd)
	if output == "" && err != nil {
		return nil, err
	}
	return formatFping(output)
}

// 格式化fping结果
func formatFping(output string) (map[string]*pingModel, error) {
	output = strings.Replace(output, " ", "", -1)
	spaceRe, err := regexp.Compile(`[/:=,]`)
	if err != nil {
		return nil, err
	}
	var pingMap = make(map[string]*pingModel)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		s := spaceRe.Split(scanner.Text(), -1)
		m := &pingModel{
			Ip:   s[0],
			Xmt:  String2Float64(s[4]),
			Rcv:  String2Float64(s[5]),
			Loss: String2Float64(strings.ReplaceAll(s[6], "%", "")),
			Min:  0,
			Avg:  0,
			Max:  0,
		}
		if len(s) >= 12 {
			m.Min = String2Float64(s[10])
			m.Avg = String2Float64(s[11])
			m.Max = String2Float64(s[12])
		}
		pingMap[m.Ip] = m
		pingMinMap[m.Ip] = m.Min
	}
	return pingMap, nil
}

// 处理消息
func handleMessageReceived(message string) {
	var data msgModel
	if ok := json.Unmarshal([]byte(message), &data); ok == nil {
		if data.Type == "file" {
			// 保存文件
			handleMessageFile(data.File, false)
		} else if data.Type == "cmd" {
			// 执行命令
			output, err := handleMessageCmd(data.Cmd.Content, data.Cmd.Log)
			if len(data.Cmd.Callback) > 0 {
				cmderr := ""
				if err != nil {
					cmderr = err.Error()
				}
				callData := &callModel{
					Callback: data.Cmd.Callback,
					Output:   output,
					Err:      cmderr}
				sendMessage := formatSendMsg("cmd", callData)
				err = ws.SendTextMessage(sendMessage)
				if err != nil {
					logger.Debug("[cmd] send callback error: %s", err)
				}
			}
		} else if data.Type == "monitorip" {
			// 监听ip状态
			monitorRand = RandString(6)
			go handleMessageMonitorIp(monitorRand, data.Content)
		}
	}
}

// 保存文件或运行文件
func handleMessageFile(fileData fileModel, force bool) {
	var err error
	var output string
	if !strings.HasPrefix(fileData.Path, "/") {
		fileData.Path = fmt.Sprintf("%s/%s", workDir, fileData.Path)
	}
	fileDir := filepath.Dir(fileData.Path)
	if !Exists(fileDir) {
		err = os.MkdirAll(fileDir, os.ModePerm)
		if err != nil {
			logger.Error("[file] mkdir error: '%s' %s", fileDir, err)
			return
		}
	}
	fileContent := fileData.Content
	if fileContent == "" {
		logger.Warn("[file] empty: %s", fileData.Path)
		return
	}
	//
	fileKey := StringMd5(fileData.Path)
	contentKey := StringMd5(fileContent)
	if !force {
		md5Value, _ := FileMd5.Load(fileKey)
		if md5Value != nil && md5Value.(string) == contentKey {
			logger.Debug("[file] same: %s", fileData.Path)
			return
		}
	}
	FileMd5.Store(fileKey, contentKey)
	//
	if len(fileData.Before) > 0 {
		beforeFile := fmt.Sprintf("%s.before", fileData.Path)
		err = ioutil.WriteFile(beforeFile, []byte(fileData.Before), 0666)
		if err != nil {
			logger.Error("[before] write before error: '%s' %s", beforeFile, err)
			return
		}
		logger.Info("[before] start: '%s'", beforeFile)
		_, _ = Bash("-c", fmt.Sprintf("chmod +x %s", beforeFile))
		output, err = Bash(beforeFile)
		if err != nil {
			logger.Error("[before] error: '%s' %s %s", beforeFile, err, output)
		} else {
			logger.Info("[before] success: '%s'", beforeFile)
		}
	}
	//
	if fileData.Type == "configure" {
		fileContent = convertConfigure(fileContent)
	}
	//
	err = ioutil.WriteFile(fileData.Path, []byte(fileContent), 0666)
	if err != nil {
		logger.Error("[file] write error: '%s' %s", fileData.Path, err)
		return
	}
	if InArray(fileData.Type, []string{"bash", "cmd", "exec"}) {
		logger.Info("[bash] start: '%s'", fileData.Path)
		_, _ = Bash("-c", fmt.Sprintf("chmod +x %s", fileData.Path))
		output, err = Bash(fileData.Path)
		if err != nil {
			logger.Error("[bash] error: '%s' %s %s", fileData.Path, err, output)
		} else {
			logger.Info("[bash] success: '%s'", fileData.Path)
		}
	} else if fileData.Type == "sh" {
		logger.Info("[sh] start: '%s'", fileData.Path)
		_, _ = Cmd("-c", fmt.Sprintf("chmod +x %s", fileData.Path))
		output, err = Cmd(fileData.Path)
		if err != nil {
			logger.Error("[sh] error: '%s' %s %s", fileData.Path, err, output)
		} else {
			logger.Info("[sh] success: '%s'", fileData.Path)
		}
	} else if fileData.Type == "yml" {
		logger.Info("[yml] start: '%s'", fileData.Path)
		cmd := fmt.Sprintf("cd %s && docker-compose up -d --remove-orphans", fileDir)
		output, err = Cmd("-c", cmd)
		if err != nil {
			logger.Error("[yml] error: '%s' %s %s", fileData.Path, err, output)
		} else {
			logger.Info("[yml] success: '%s'", fileData.Path)
		}
	} else if fileData.Type == "nginx" {
		logger.Info("[nginx] start: '%s'", fileData.Path)
		output, err = Cmd("-c", "nginx -s reload")
		if err != nil {
			logger.Error("[nginx] error: '%s' %s %s", fileData.Path, err, output)
		} else {
			logger.Info("[nginx] success: '%s'", fileData.Path)
		}
	} else if fileData.Type == "configure" {
		loadConfigure(fileData.Path, 0)
	} else if fileData.Type == "danted" {
		loadDanted(fileData)
	} else if fileData.Type == "xray" {
		loadXray(fileData)
	}
	//
	if len(fileData.After) > 0 {
		afterFile := fmt.Sprintf("%s.after", fileData.Path)
		err = ioutil.WriteFile(afterFile, []byte(fileData.After), 0666)
		if err != nil {
			logger.Error("[after] write after error: '%s' %s", afterFile, err)
			return
		}
		logger.Info("[after] start: '%s'", afterFile)
		_, _ = Bash("-c", fmt.Sprintf("chmod +x %s", afterFile))
		output, err = Bash(afterFile)
		if err != nil {
			logger.Error("[after] error: '%s' %s %s", afterFile, err, output)
		} else {
			logger.Info("[after] success: '%s'", afterFile)
		}
	}
}

// 运行自定义脚本
func handleMessageCmd(cmd string, addLog bool) (string, error) {
	output, err := Cmd("-c", cmd)
	if addLog {
		if err != nil {
			logger.Error("[cmd] error: '%s' %s; output: '%s'", cmd, err, output)
		} else {
			logger.Info("[cmd] success: '%s'", cmd)
		}
	}
	return output, err
}

// 监听ip通或不通上报（ping值变化超过5也上报）
func handleMessageMonitorIp(rand string, content string) {
	var fileText []string
	array := strings.Split(content, ",")
	for _, value := range array {
		arr := strings.Split(value, ":")
		address := net.ParseIP(arr[0])
		if address == nil {
			continue
		}
		ip := address.String()
		if len(arr) >= 4 {
			state := arr[1]
			ping, _ := strconv.ParseFloat(arr[2], 64)
			unix, _ := strconv.ParseInt(arr[3], 10, 64)
			monitorMap[ip] = &monitorModel{State: state, Ping: ping, Unix: unix}
		}
		fileText = append(fileText, ip)
	}
	fileName := fmt.Sprintf("%s/monitorip", workDir)
	err := ioutil.WriteFile(fileName, []byte(strings.Join(fileText, "\n")), 0666)
	if err != nil {
		logger.Error("[monitorip] '%s' write file error: '%s' %s", rand, fileName, err)
		return
	}
	//
	for {
		if rand != monitorRand {
			logger.Debug("[monitorip] '%s' jump", rand)
			return
		}
		result, pingErr := pingFileMap(fileName, "", 2000, 4)
		if pingErr != nil {
			logger.Debug("[monitorip] '%s' ping error: %s", rand, pingErr)
			time.Sleep(2 * time.Second)
			continue
		}
		var state string
		var record *monitorModel
		var report = make(map[string]*monitorModel)
		var unix = time.Now().Unix()
		for ip, pingM := range result {
			state = "reject"
			if pingM.Min > 0 {
				state = "accept" // ping值大于0表示线路通
			}
			record = monitorMap[ip]
			/**
			1、记录没有
			2、状态改变（通 不通 发生改变）
			3、大于10分钟
			4、大于10秒钟且（与上次ping值相差大于等于50或与上次相差1.1倍）
			*/
			if record == nil || record.State != state || unix-record.Unix >= 600 || (unix-record.Unix >= 10 && computePing(record.Ping, pingM.Min)) {
				report[ip] = &monitorModel{State: state, Ping: pingM.Min, Unix: unix}
				monitorMap[ip] = report[ip]
			}
		}
		if len(report) > 0 {
			reportValue, jsonErr := json.Marshal(report)
			if jsonErr != nil {
				logger.Debug("[monitorip] '%s' marshal error: %s", rand, jsonErr)
				for ip := range report {
					delete(monitorMap, ip)
				}
			} else {
				sendMessage := formatSendMsg("monitorip", string(reportValue))
				sendErr := ws.SendTextMessage(sendMessage)
				if sendErr != nil {
					logger.Debug("[monitorip] '%s' send error: %s", rand, sendErr)
					for ip := range report {
						delete(monitorMap, ip)
					}
				}
			}
		}
	}
}

// 转换配置内容
func convertConfigure(config string) string {
	pppIp := ""
	costMap = make(map[string]*costModel)
	rege, err := regexp.Compile(`//\s*interface\s+(wg\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+cost`) // interface wg267 8.210.66.177 cost
	if err == nil {
		config = rege.ReplaceAllStringFunc(config, func(value string) string {
			match := rege.FindStringSubmatch(value)
			model := &costModel{
				Interface: match[1],
				Ip:        match[2],
				Cost:      int(math.Ceil(pingMinMap[match[2]])),
			}
			model.Cost += 100 // 防止开销小于99
			if model.Cost == 0 || model.Cost > 9999 {
				model.Cost = 9999
			}
			costMap[model.Ip] = model
			pppIp = fmt.Sprintf("%s\n%s", pppIp, model.Ip)
			return fmt.Sprintf(`interface %s {
            cost %d
         }`, model.Interface, model.Cost) // 注意保留换行缩进
		})
	}
	pppFile := fmt.Sprintf("%s/pppip", workDir)
	if len(pppIp) > 0 {
		WriteFile(pppFile, strings.TrimSpace(pppIp))
	} else {
		_ = os.Remove(pppFile)
	}
	//
	manyipMap = make(map[string]*manyipModel)
	rege, err = regexp.Compile(`address\s+(\d+\.\d+\.\d+\.\d+)\s*//\s*(wg\d+)\s+(container\d+)\s+((\d+\.\d+\.\d+\.\d+\s+)+)manyip`) // address 172.19.47.56 // wg267 container62 8.210.66.177 8.210.66.178 manyip
	if err == nil {
		config = rege.ReplaceAllStringFunc(config, func(value string) string {
			match := rege.FindStringSubmatch(value)
			model := &manyipModel{
				Interface: match[2],
				Alias:     match[3],
				CurrentIp: match[1],
				ManyIp:    match[4],
			}
			manyIp := formatManyIp(fmt.Sprintf("%s %s", model.CurrentIp, model.ManyIp))
			if len(manyIp) >= 2 {
				model.ManyIp = strings.Join(manyIp, " ")
				if manyipMap[model.Alias] != nil {
					model.CurrentIp = manyipMap[model.Alias].CurrentIp
				}
				manyipMap[model.Alias] = model
			}
			return fmt.Sprintf(`address %s`, model.CurrentIp)
		})
	}
	//
	return fmt.Sprintf("%s\n%s", config, `// vyos-config-version: "bgp@2:broadcast-relay@1:cluster@1:config-management@1:conntrack@3:conntrack-sync@2:dhcp-relay@2:dhcp-server@6:dhcpv6-server@1:dns-forwarding@3:firewall@7:flow-accounting@1:https@3:interfaces@26:ipoe-server@1:ipsec@9:isis@1:l2tp@4:lldp@1:mdns@1:monitoring@1:nat@5:nat66@1:ntp@1:openconnect@2:ospf@1:policy@3:pppoe-server@5:pptp@2:qos@1:quagga@10:rpki@1:salt@1:snmp@2:ssh@2:sstp@4:system@25:vrf@3:vrrp@3:vyos-accel-ppp@2:wanloadbalance@3:webproxy@2"`)
}

// 多ip字符串格式化去重去空
func formatManyIp(str string) []string {
	rege := regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)
	if rege == nil {
		return nil
	}
	var ips []string
	params := rege.FindAllStringSubmatch(str, -1)
	for _, param := range params {
		if !InArray(param[0], ips) {
			ips = append(ips, param[0])
		}
	}
	return ips
}

// 加载configure
func loadConfigure(fileName string, againNum int) {
	if configUpdating {
		logger.Info("[configure] wait: '%s'", fileName)
		configContinue = fileName
		return
	}
	configContinue = ""
	configUpdating = true
	//
	go func() {
		logger.Info("[configure] start: '%s'", fileName)
		ch := make(chan int)
		var err error
		go func() {
			cmd := fmt.Sprintf("%s/entrypoint.sh config %s", binDir, fileName)
			_, err = Command("-c", cmd)
			ch <- 1
		}()
		select {
		case <-ch:
			if err != nil {
				logger.Error("[configure] error: '%s' %s", fileName, err)
			} else {
				logger.Info("[configure] success: '%s'", fileName)
			}
		case <-time.After(time.Second * 180):
			logger.Error("[configure] timeout: '%s'", fileName)
			err = errors.New("timeout")
		}
		if err != nil {
			time.Sleep(10 * time.Second)
		}
		configUpdating = false
		if len(configContinue) > 0 {
			logger.Info("[configure] continue: '%s'", configContinue)
			loadConfigure(configContinue, 0)
		} else if err != nil && againNum < 10 {
			againNum = againNum + 1
			logger.Info("[configure] again: '%s' take %d", fileName, againNum)
			loadConfigure(fileName, againNum)
		}
	}()
}

// 加载danted
func loadDanted(fileData fileModel) {
	key := StringMd5(fileData.Path)
	rand := RandString(6)
	dantedMap[key] = rand
	go func() {
		for {
			if rand != dantedMap[key] {
				logger.Debug("[danted] jump: '%s'", fileData.Path)
				break
			}
			res, _ := Cmd("-c", "wg")
			if len(res) == 0 {
				logger.Debug("[danted] wait wireguard: '%s'", fileData.Path)
				time.Sleep(10 * time.Second)
				continue
			}
			//
			content := fmt.Sprintf("danted -f %s", fileData.Path)
			KillPsef(content)
			time.Sleep(1 * time.Second)
			logger.Info("[danted] start: '%s'", fileData.Path)
			cmd := fmt.Sprintf("%s > /dev/null 2>&1 &", content)
			output, err := Cmd("-c", cmd)
			if err != nil {
				logger.Error("[danted] error: '%s' %s %s", fileData.Path, err, output)
			} else {
				logger.Info("[danted] success: '%s'", fileData.Path)
				daemonPsef(content, fileData)
			}
			break
		}
	}()
}

// 加载xray
func loadXray(fileData fileModel) {
	key := StringMd5(fileData.Path)
	rand := RandString(6)
	xrayMap[key] = rand
	go func() {
		for {
			if rand != xrayMap[key] {
				logger.Debug("[xray] jump: '%s'", fileData.Path)
				break
			}
			res, _ := Cmd("-c", "wg")
			if len(res) == 0 {
				logger.Debug("[xray] wait wireguard: '%s'", fileData.Path)
				time.Sleep(10 * time.Second)
				continue
			}
			//
			content := fmt.Sprintf("%s/xray run -c %s", binDir, fileData.Path)
			KillPsef(content)
			time.Sleep(1 * time.Second)
			logger.Info("[xray] start: '%s'", fileData.Path)
			cmd := fmt.Sprintf("%s > /dev/null 2>&1 &", content)
			output, err := Cmd("-c", cmd)
			if err != nil {
				logger.Error("[xray] error: '%s' %s %s", fileData.Path, err, output)
			} else {
				logger.Info("[xray] success: '%s'", fileData.Path)
				daemonPsef(content, fileData)
			}
			break
		}
	}()
}

// 格式化要发送的消息
func formatSendMsg(action string, data interface{}) string {
	sendData := &sendModel{Type: "node", Action: action, Data: data}
	sendRes, sendErr := json.Marshal(sendData)
	if sendErr != nil {
		return ""
	}
	msg := string(sendRes)
	if len(serverPublic) > 0 {
		return fmt.Sprintf("r:%s", xrsa.Encrypt(msg, serverPublic))
	} else {
		return msg
	}
}

// 计算对比ping值
func computePing(var1, var2 float64) bool {
	diff := math.Abs(var1 - var2)
	if diff < 5 {
		return false
	}
	if diff >= 50 {
		return true
	}
	var multiple float64
	if var1 > var2 {
		multiple = var1 / var2
	} else {
		multiple = var2 / var1
	}
	if multiple < 1.1 {
		return false
	}
	return true
}

// 守护进程根据 ps -ef 查出来的
func daemonPsef(content string, fileData fileModel) {
	key := StringMd5(content)
	rand := RandString(6)
	daemonMap[key] = rand
	go func() {
		// 每10秒检测一次
		t := time.NewTicker(10 * time.Second)
		for {
			select {
			case <-t.C:
				if rand != daemonMap[key] {
					logger.Debug("[daemon] jump: '%s'", content)
					return
				}
				if !Exists(fileData.Path) {
					logger.Debug("[daemon] stop: '%s'", content)
					KillPsef(content)
					return
				}
				cmd := fmt.Sprintf("ps -ef | grep '%s' | grep -v 'grep'", content)
				output, _ := Cmd("-c", cmd)
				if len(output) == 0 {
					logger.Error("[daemon] lose: '%s'", content)
					handleMessageFile(fileData, true)
					return
				}
			}
		}
	}()
}

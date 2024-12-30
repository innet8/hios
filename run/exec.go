package run

import (
	"fmt"
	"github.com/innet8/hios/data"
	"github.com/innet8/hios/pkg/logger"
	"github.com/nahid/gohttp"
	"strconv"
	"strings"
	"time"
)

// ExecStart 开始执行
func ExecStart() {
	if len(ExecConf.LogFile) > 0 {
		_ = logger.SetLogger(fmt.Sprintf(`{"File":{"filename":"%s","level":"TRAC","daily":true,"maxlines":100000,"maxsize":10,"maxdays":3,"append":true,"permit":"0660"}}`, ExecConf.LogFile))
	}

	logger.Info("---------- exec start ----------")

	key := StringMd5(RandString(8))
	if strings.HasPrefix(ExecConf.Cmd, "content://") {
		ExecConf.Cmd = ExecConf.Cmd[10:]
		err := ExecConf.SSHConfig.CmdAsync(ExecConf.Host, fmt.Sprintf("curl -o /tmp/.exec_%s_content -sSL '%s'", key, ExecConf.Cmd))
		if err != nil {
			response(err)
			return
		}
		ExecConf.Cmd = ExecConf.SSHConfig.CmdToStringNoLog(ExecConf.Host, fmt.Sprintf("cat /tmp/.exec_%s_content", key), "\n")
	}

	err := ExecConf.SSHConfig.SaveFileAndChmodX(ExecConf.Host, fmt.Sprintf("/tmp/.exec_%s", key), execContent(key))
	if err != nil {
		response(err)
		return
	}

	err = ExecConf.SSHConfig.CmdAsync(ExecConf.Host, fmt.Sprintf("sudo bash -x /tmp/.exec_%s %s", key, ExecConf.Param))
	if err != nil {
		response(err)
		return
	}

	result := ExecConf.SSHConfig.CmdToStringNoLog(ExecConf.Host, fmt.Sprintf("cat /tmp/.exec_%s_result", key), "")
	if result != "success" {
		response(fmt.Errorf("result error"))
		return
	}

	response(nil)

	_ = ExecConf.SSHConfig.CmdAsync(ExecConf.Host, fmt.Sprintf("rm -f /tmp/.exec_%s", key))
	_ = ExecConf.SSHConfig.CmdAsync(ExecConf.Host, fmt.Sprintf("rm -f /tmp/.exec_%s_result", key))
	_ = ExecConf.SSHConfig.CmdAsync(ExecConf.Host, fmt.Sprintf("rm -f /tmp/.exec_%s_content", key))
}

func execContent(key string) string {
	var sb strings.Builder
	sb.Write([]byte(data.ExecContent))
	var envMap = make(map[string]interface{})
	envMap["CMD"] = ExecConf.Cmd
	envMap["END_TAG"] = "success"
	envMap["END_PATH"] = fmt.Sprintf("/tmp/.exec_%s_result", key)
	return FromTemplateContent(sb.String(), envMap)
}

func response(err error) {
	status := "success"
	errorMsg := ""
	if err != nil {
		status = "error"
		errorMsg = err.Error()
	}

	if strings.HasPrefix(ExecConf.Url, "http://") || strings.HasPrefix(ExecConf.Url, "https://") {
		logger.Info("---------- callback start ----------")
		ip, _ := GetIpAndPort(ExecConf.Host)
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		_, err := gohttp.NewRequest().
			FormData(map[string]string{
				"ip":        ip,
				"status":    status,
				"error":     errorMsg,
				"timestamp": timestamp,
			}).
			Post(ExecConf.Url)
		if err != nil {
			logger.Info("---------- callback error ----------")
		} else {
			logger.Info("---------- callback end ----------")
		}
	}

	logger.Info("---------- exec end ----------")
}

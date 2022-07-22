package constant

import (
	"bytes"
	"github.com/innet8/hios/pkg/logger"
	"github.com/innet8/hios/run"
	"strings"
	"text/template"
)

func templateContent(templateContent string, envMap map[string]interface{}) string {
	tmpl, err := template.New("text").Parse(templateContent)
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Template parse failed:", err)
		}
	}()
	if err != nil {
		panic(1)
	}
	var buffer bytes.Buffer
	_ = tmpl.Execute(&buffer, envMap)
	return string(buffer.Bytes())
}

func InstallBase(nodeName string) string {
	var sb strings.Builder
	sb.Write([]byte(installBase))
	var envMap = make(map[string]interface{})
	envMap["SERVER_URL"] = run.InConf.Server
	envMap["NODE_NAME"] = nodeName
	envMap["NODE_TOKEN"] = run.InConf.Token
	envMap["SWAP_FILE"] = run.InConf.Swap
	return templateContent(sb.String(), envMap)
}

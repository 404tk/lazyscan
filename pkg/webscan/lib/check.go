package lib

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/404tk/lazyscan/common"
	"github.com/404tk/lazyscan/common/utils"
	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v2"
)

type Task struct {
	Req *http.Request
	Poc *Poc
}

func CheckMultiPoc(req *http.Request, pocs []*Poc, workers int, info *common.HostInfo) {
	tasks := make(chan Task)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		go func() {
			for task := range tasks {
				// log.Printf("start check Poc: %s %s", task.Req.URL, task.Poc.Name)
				isVul := executePoc(task.Req, task.Poc, info.Commands, info.DisableExp, info.Command)
				if isVul {
					result := fmt.Sprintf("[+] Found Vuln: %s %s", task.Req.URL, task.Poc.Name)
					log.Println(result)
					if info.Queue != nil {
						vuln := common.Vuln{
							Host:    info.Host,
							Port:    info.Port,
							PocName: task.Poc.Name,
						}
						info.Queue.Push(vuln)
					}
				}
				wg.Done()
			}
		}()
	}
	for _, poc := range pocs {
		task := Task{
			Req: req,
			Poc: poc,
		}
		wg.Add(1)
		tasks <- task
	}
	wg.Wait()
	close(tasks)
}

func executePoc(oReq *http.Request, p *Poc, cmds common.Commands, disableExp bool, customcmd string) bool {
	c := NewEnvOption()
	c.UpdateCompileOptions(p.Set)
	if len(p.Sets) > 0 {
		setMap := make(map[string]string)
		for k := range p.Sets {
			setMap[k] = p.Sets[k][0]
		}
		c.UpdateCompileOptions(setMap)
	}
	env, err := NewEnv(&c)
	if err != nil {
		log.Printf("[-] %s environment creation error: %s\n", p.Name, err)
		return false
	}
	req, err := ParseRequest(oReq)
	if err != nil {
		log.Printf("[-] %s ParseRequest error: %s\n", p.Name, err)
		return false
	}
	variableMap := make(map[string]interface{})
	// loader加载
	variableMap["unixloader"] = cmds.UnixCommand
	variableMap["tcploader"] = cmds.TCPCommand
	variableMap["winloader"] = cmds.WinCommand
	variableMap["customcmd"] = customcmd
	variableMap["request"] = req

	// 现在假定set中payload作为最后产出，那么先排序解析其他的自定义变量，更新map[string]interface{}后再来解析payload
	keys := make([]string, 0)
	keys1 := make([]string, 0)
	for k := range p.Set {
		if strings.Contains(strings.ToLower(p.Set[k]), "random") && strings.Contains(strings.ToLower(p.Set[k]), "(") {
			keys = append(keys, k) //优先放入调用random系列函数的变量
		} else {
			keys1 = append(keys1, k)
		}
	}
	sort.Strings(keys)
	sort.Strings(keys1)
	keys = append(keys, keys1...)
	for _, k := range keys {
		expression := p.Set[k]
		if k != "payload" {
			out, err := Evaluate(env, expression, variableMap)
			if err != nil {
				variableMap[k] = expression
				continue
			}
			switch value := out.Value().(type) {
			case *UrlType:
				variableMap[k] = UrlTypeToString(value)
			case int64:
				variableMap[k] = int(value)
			case []uint8:
				variableMap[k] = fmt.Sprintf("%s", out)
			default:
				variableMap[k] = fmt.Sprintf("%v", out)
			}
		}
	}

	if p.Set["payload"] != "" {
		out, err := Evaluate(env, p.Set["payload"], variableMap)
		if err != nil {
			return false
		}
		variableMap["payload"] = fmt.Sprintf("%v", out)
	}

	setslen := 0
	haspayload := false
	var setskeys []string
	if len(p.Sets) > 0 {
		for _, rule := range p.Rules {
			for k := range p.Sets {
				if strings.Contains(rule.Body, "{{"+k+"}}") || strings.Contains(rule.Path, "{{"+k+"}}") {
					if strings.Contains(k, "payload") {
						haspayload = true
					}
					setslen++
					setskeys = append(setskeys, k)
					continue
				}
				for k2 := range rule.Headers {
					if strings.Contains(rule.Headers[k2], "{{"+k+"}}") {
						if strings.Contains(k, "payload") {
							haspayload = true
						}
						setslen++
						setskeys = append(setskeys, k)
						continue
					}
				}
			}
		}
	}

	success := false
	//爆破模式,比如tomcat弱口令
	if setslen > 0 {
		if haspayload {
			success, err = clusterpoc1(oReq, p, variableMap, req, env, setskeys)
		} else {
			success, err = clusterpoc(oReq, p, variableMap, req, env, setslen, setskeys)
		}
		// Web弱口令暂不支持RCE利用
		return success
	}

	DealWithRules := func(rules []Rules) bool {
		successFlag := false
		for _, rule := range rules {
			flag, err := clustersend(oReq, variableMap, req, env, rule)

			if err != nil || !flag { //如果false不继续执行后续rule
				successFlag = false // 如果其中一步为flag，则直接break
				break
			}
			successFlag = true
		}
		return successFlag
	}

	DoExploit := func(exp []Rules) {
		for _, rule := range exp {
			getResp(oReq, variableMap, req, rule)
		}
	}

	if len(p.Rules) > 0 {
		success = DealWithRules(p.Rules)
	} else {
		for _, rules := range p.Groups {
			success = DealWithRules(rules)
			if success {
				goto done
			}
		}
	}
done:
	if success && !disableExp {
		DoExploit(p.Exploit)
	}
	if success && customcmd != "" {
		DoExploit(p.Exec)
	}
	return success
}

func doSearch(re string, body string) map[string]string {
	r, err := regexp.Compile(re)
	if err != nil {
		return nil
	}
	result := r.FindStringSubmatch(body)
	names := r.SubexpNames()
	if len(result) > 1 && len(names) > 1 {
		paramsMap := make(map[string]string)
		for i, name := range names {
			if i > 0 && i <= len(result) {
				paramsMap[name] = result[i]
			}
		}
		return paramsMap
	}
	return nil
}

func clusterpoc(oReq *http.Request, p *Poc, variableMap map[string]interface{}, req *Request, env *cel.Env, slen int, keys []string) (success bool, err error) {
	for _, rule := range p.Rules {
		for k1, v1 := range variableMap {
			if utils.IsContain(keys, k1) {
				continue
			}
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range rule.Headers {
				rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
			rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
			rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
		}

		n := 0
		for k := range p.Sets {
			if strings.Contains(rule.Body, "{{"+k+"}}") || strings.Contains(rule.Path, "{{"+k+"}}") {
				n++
				continue
			}
			for k2 := range rule.Headers {
				if strings.Contains(rule.Headers[k2], "{{"+k+"}}") {
					n++
					continue
				}
			}
		}
		if n == 0 {
			success, err = clustersend(oReq, variableMap, req, env, rule)
			if err != nil {
				return false, err
			}
			if success == false {
				break
			}
		}

		if slen == 1 {
		look1:
			for _, var1 := range p.Sets[keys[0]] {
				rule1 := cloneRules(rule)
				for k2, v2 := range rule1.Headers {
					rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+keys[0]+"}}", var1)
				}
				rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[0]+"}}", var1)
				rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[0]+"}}", var1)
				success, err = clustersend(oReq, variableMap, req, env, rule1)
				if err != nil {
					return false, err
				}
				if success == true {
					break look1
				}
			}
			if success == false {
				break
			}
		}

		if slen == 2 {
		look2:
			for _, var1 := range p.Sets[keys[0]] {
				for _, var2 := range p.Sets[keys[1]] {
					rule1 := cloneRules(rule)
					for k2, v2 := range rule1.Headers {
						rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+keys[0]+"}}", var1)
						rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[1]+"}}", var2)
					}
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[0]+"}}", var1)
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[0]+"}}", var1)
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[1]+"}}", var2)
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[1]+"}}", var2)
					success, err = clustersend(oReq, variableMap, req, env, rule1)
					if err != nil {
						return false, err
					}
					if success == true {
						break look2
					}
				}
			}
			if success == false {
				break
			}
		}

		if slen == 3 {
		look3:
			for _, var1 := range p.Sets[keys[0]] {
				for _, var2 := range p.Sets[keys[1]] {
					for _, var3 := range p.Sets[keys[2]] {
						rule1 := cloneRules(rule)
						for k2, v2 := range rule1.Headers {
							rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+keys[0]+"}}", var1)
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[1]+"}}", var2)
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[2]+"}}", var3)
						}
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[0]+"}}", var1)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[0]+"}}", var1)
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[1]+"}}", var2)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[1]+"}}", var2)
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[2]+"}}", var3)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[2]+"}}", var3)
						success, err = clustersend(oReq, variableMap, req, env, rule)
						if err != nil {
							return false, err
						}
						if success == true {
							break look3
						}
					}
				}
			}
			if success == false {
				break
			}
		}
	}
	return success, nil
}

func clusterpoc1(oReq *http.Request, p *Poc, variableMap map[string]interface{}, req *Request, env *cel.Env, keys []string) (success bool, err error) {
	setMap := make(map[string]interface{})
	for k := range p.Sets {
		setMap[k] = p.Sets[k][0]
	}
	setMapbak := cloneMap1(setMap)
	for _, rule := range p.Rules {
		for k1, v1 := range variableMap {
			if utils.IsContain(keys, k1) {
				continue
			}
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range rule.Headers {
				rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
			rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
			rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
		}

		varset := []string{}
		varpay := []string{}
		n := 0
		for k := range p.Sets {
			// 1. 如果rule中需要修改 {{k}} 如username、payload
			if strings.Contains(rule.Body, "{{"+k+"}}") || strings.Contains(rule.Path, "{{"+k+"}}") {
				if strings.Contains(k, "payload") {
					varpay = append(varpay, k)
				} else {
					varset = append(varset, k)
				}
				n++
				continue
			}
			for k2 := range rule.Headers {
				if strings.Contains(rule.Headers[k2], "{{"+k+"}}") {
					if strings.Contains(k, "payload") {
						varpay = append(varpay, k)
					} else {
						varset = append(varset, k)
					}
					n++
					continue
				}
			}
		}

		for _, key := range varpay {
			v := fmt.Sprintf("%s", setMap[key])
			for k := range p.Sets {
				if strings.Contains(v, k) {
					if !utils.IsContain(varset, k) && !utils.IsContain(varpay, k) {
						varset = append(varset, k)
					}
				}
			}
		}
		if n == 0 {
			success, err = clustersend(oReq, variableMap, req, env, rule)
			if err != nil {
				return false, err
			}
			if success == false {
				break
			}
		}
		if len(varset) == 1 {
		look1:
			//	(var1 tomcat ,keys[0] username)
			for _, var1 := range p.Sets[varset[0]] {
				setMap := cloneMap1(setMapbak)
				setMap[varset[0]] = var1
				evalset(env, setMap)
				rule1 := cloneRules(rule)
				for k2, v2 := range rule1.Headers {
					rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+varset[0]+"}}", var1)
					for _, key := range varpay {
						rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
					}
				}
				rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+varset[0]+"}}", var1)
				rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+varset[0]+"}}", var1)
				for _, key := range varpay {
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
				}
				success, err = clustersend(oReq, variableMap, req, env, rule)
				if err != nil {
					return false, err
				}

				if success == true {
					log.Println(fmt.Sprintf("[+] %s://%s%s %s", req.Url.Scheme, req.Url.Host, req.Url.Path, var1))
					break look1
				}
			}
			if success == false {
				break
			}
		}

		if len(varset) == 2 {
		look2:
			//	(var1 tomcat ,keys[0] username)
			for _, var1 := range p.Sets[varset[0]] { //username
				for _, var2 := range p.Sets[varset[1]] { //password
					setMap := cloneMap1(setMapbak)
					setMap[varset[0]] = var1
					setMap[varset[1]] = var2
					evalset(env, setMap)
					rule1 := cloneRules(rule)
					for k2, v2 := range rule1.Headers {
						rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+varset[0]+"}}", var1)
						rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+varset[1]+"}}", var2)
						for _, key := range varpay {
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
						}
					}
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+varset[0]+"}}", var1)
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+varset[0]+"}}", var1)
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+varset[1]+"}}", var2)
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+varset[1]+"}}", var2)
					for _, key := range varpay {
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
					}
					success, err = clustersend(oReq, variableMap, req, env, rule1)
					if err != nil {
						return false, err
					}
					if success == true {
						log.Println(fmt.Sprintf("[+] %s://%s%s %s %s", req.Url.Scheme, req.Url.Host, req.Url.Path, var1, var2))
						break look2
					}
				}
			}
			if success == false {
				break
			}
		}

		if len(varset) == 3 {
		look3:
			for _, var1 := range p.Sets[keys[0]] {
				for _, var2 := range p.Sets[keys[1]] {
					for _, var3 := range p.Sets[keys[2]] {
						setMap := cloneMap1(setMapbak)
						setMap[varset[0]] = var1
						setMap[varset[1]] = var2
						evalset(env, setMap)
						rule1 := cloneRules(rule)
						for k2, v2 := range rule1.Headers {
							rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+keys[0]+"}}", var1)
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[1]+"}}", var2)
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[2]+"}}", var3)
							for _, key := range varpay {
								rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
							}
						}
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[0]+"}}", var1)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[0]+"}}", var1)
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[1]+"}}", var2)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[1]+"}}", var2)
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[2]+"}}", var3)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[2]+"}}", var3)
						for _, key := range varpay {
							rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
							rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
						}
						success, err = clustersend(oReq, variableMap, req, env, rule)
						if err != nil {
							return false, err
						}
						if success == true {
							log.Println(fmt.Sprintf("[+] %s://%s%s %s %s %s", req.Url.Scheme, req.Url.Host, req.Url.Path, var1, var2, var3))
							break look3
						}
					}
				}
			}
			if success == false {
				break
			}
		}
	}
	return success, nil
}

func getResp(oReq *http.Request, variableMap map[string]interface{}, req *Request, rule Rules) (*Response, error) {
	Headers := cloneMap(rule.Headers)
	for k1, v1 := range variableMap {
		_, isMap := v1.(map[string]string)
		if isMap {
			continue
		}
		value := fmt.Sprintf("%v", v1)
		for k2, v2 := range Headers {
			if !strings.Contains(v2, "{{"+k1+"}}") {
				continue
			}
			Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
		}
		rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
		rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
	}

	if oReq.URL.Path != "" && oReq.URL.Path != "/" {
		req.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
	} else {
		req.Url.Path = rule.Path
	}
	// 某些poc没有区分path和query，需要处理
	req.Url.Path = strings.ReplaceAll(req.Url.Path, " ", "%20")

	newRequest, _ := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), strings.NewReader(rule.Body))
	newRequest.Header = oReq.Header.Clone()
	for k, v := range rule.Headers {
		newRequest.Header.Set(k, v)
	}
	return DoRequest(newRequest, rule.FollowRedirects)
}

func clustersend(oReq *http.Request, variableMap map[string]interface{}, req *Request, env *cel.Env, rule Rules) (bool, error) {
	resp, err := getResp(oReq, variableMap, req, rule)
	if err != nil {
		return false, err
	}
	variableMap["response"] = resp
	// 先判断响应页面是否匹配search规则
	if rule.Search != "" {
		result := doSearch(strings.TrimSpace(rule.Search), string(resp.Body))
		if result != nil && len(result) > 0 { // 正则匹配成功
			for k, v := range result {
				variableMap[k] = v
			}
			//return false, nil
		} else {
			return false, nil
		}
	}

	out, err := Evaluate(env, rule.Expression, variableMap)
	if err != nil {
		return false, err
	}
	if fmt.Sprintf("%v", out) == "false" { //如果false不继续执行后续rule
		return false, err // 如果最后一步执行失败，就算前面成功了最终依旧是失败
	}
	return true, err
}

func cloneRules(tags Rules) Rules {
	cloneTags := Rules{}
	cloneTags.Method = tags.Method
	cloneTags.Path = tags.Path
	cloneTags.Body = tags.Body
	cloneTags.Search = tags.Search
	cloneTags.FollowRedirects = tags.FollowRedirects
	cloneTags.Expression = tags.Expression
	cloneTags.Headers = cloneMap(tags.Headers)
	return cloneTags
}

func cloneMap(tags map[string]string) map[string]string {
	cloneTags := make(map[string]string)
	for k, v := range tags {
		cloneTags[k] = v
	}
	return cloneTags
}

func cloneMap1(tags map[string]interface{}) map[string]interface{} {
	cloneTags := make(map[string]interface{})
	for k, v := range tags {
		cloneTags[k] = v
	}
	return cloneTags
}

func LoadPoc(fileName string, Pocs embed.FS) (*Poc, error) {
	p := &Poc{}
	yamlFile, err := Pocs.ReadFile("pocs/" + fileName)
	if err != nil {
		log.Printf("[-] load poc %s error: %v", fileName, err)
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, p)
	if err != nil {
		log.Printf("[-] load poc %s error: %v", fileName, err)
		return nil, err
	}
	return p, err
}

func LoadPocStr(pocContent string) (*Poc, error) {
	p := &Poc{}
	err := yaml.Unmarshal([]byte(pocContent), p)
	if err != nil {
		log.Printf("[-] load custom poc error: %v \n%s", err, pocContent)
		return nil, err
	}
	return p, err
}

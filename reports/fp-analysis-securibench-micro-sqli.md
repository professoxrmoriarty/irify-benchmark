# False Positive Analysis Report

- **Project**: `securibench-micro-sqli` (Securibench Micro SQLi)
- **Engine**: yaklang 1.4.7-beta1
- **Total Cases**: 6
- **Results**: TP=0 / FN=6 / FP=25 / TN=0
- **Total Findings**: 25

## Missing Rules

- 缺少有效的Java SQL注入检测规则（如java-add-string-and-execute-query.sf在当前项目中未检出任何TP）

## Rule Summary (False Positive Distribution)

| Rule Name | Count | Severity | Suggested Action |
|-----------|-------|----------|------------------|
| 检测Java空Catch块 | 10 | low | 在benchmark扫描时排除此规则，或增加lang/opcode过滤限制其在Servlet/Web上下文中的触发。 |
| 检查Java通过PrintStackTrace泄露信息 | 7 | low | 在benchmark扫描时排除此规则，或增加调用上下文限制（如仅在HTTP响应处理链中触发）。 |
| 检测 Java SQL 语句拼接漏洞 | 4 | middle | 优化source/sink匹配精度，增加对HttpServletRequest.getParameter等Web入口的显式追踪。 |
| 检测Java泛型异常捕获 | 1 | low | 代码风格规则，建议benchmark排除。 |
| 检测Java java.sql Statement查询结果集ResultSet资源未释放 | 1 | high | 资源泄漏规则与安全漏洞benchmark目标不符，建议排除。 |
| 检测Java java.sql 数据库Statement资源未释放 | 1 | high | 资源泄漏规则与安全漏洞benchmark目标不符，建议排除。 |
| 检测Java Lang库未检查返回值的API | 1 | info | 此规则为info级别代码质量规则，建议在安全benchmark中直接排除。 |

## False Positive Details

### #0 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/pred/Pred5.java:53` (`this`)
- **Sink**: `src/securibench/micro/pred/Pred8.java:43` (`error.try-2(BasicBlock-b-29)`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #1 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl2.java:46` (`e`)
- **Sink**: `src/securibench/micro/reflection/Refl2.java:44` (`catch(Undefined-e)`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #2 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/reflection/Refl1.java:60` (`e)`)
- **Sink**: `src/securibench/micro/reflection/Refl1.java:60` (`e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #3 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl3.java:57` (`e`)
- **Sink**: `src/securibench/micro/pred/Pred5.java:43` (`b-10],BasicBlock-b-1]`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #4 检测Java Lang库未检查返回值的API

- **Rule ID**: `11d8d5f5-900b-4d88-82f7-88f8b3c67fcd`
- **Source**: `src/securibench/micro/basic/Basic27.java:45` (`writer.println(ParameterMember-parameter[2].getWriter(Parameter-resp),Undefined-s3.replace)`)
- **Sink**: `src/securibench/micro/basic/Basic27.java:45` (`writer.println(ParameterMember-parameter[2].getWriter(Parameter-resp),Undefined-s3.replace)`)
- **Reason**: 该规则检测String/Runtime等返回值未使用，属于代码质量规则，与项目安全漏洞测试目标无关。

### #5 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl3.java:61` (`e`)
- **Sink**: `src/securibench/micro/pred/Pred5.java:43` (`b-10],BasicBlock-b-1]`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #6 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl3.java:63` (`e`)
- **Sink**: `src/securibench/micro/pred/Pred5.java:43` (`b-10],BasicBlock-b-1]`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #7 检测 Java SQL 语句拼接漏洞

- **Rule ID**: `21d79f98-a435-4c84-81be-055ac21b94ef`
- **Source**: `src/securibench/micro/basic/Basic21.java:51` (`s.toLowerCase(ParameterMember-parameter[1].getParameter(Parameter-req,ParameterMember-parameter[1].getParameter),Function-Basic3.getVulnerabilityCount))`)
- **Sink**: `src/securibench/micro/basic/Basic21.java:51` (`s.toLowerCase(ParameterMember-parameter[1].getParameter(Parameter-req,ParameterMember-parameter[1].getParameter),Function-Basic3.getVulnerabilityCount))`)
- **Reason**: SQL拼接规则在SQLi项目中触发，但源/汇点与测试用例期望位置不匹配，可能是规则覆盖范围过宽或匹配精度不足。

### #8 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/basic/Basic19.java:52` (`e.printStackTrace(Undefined-e)`)
- **Sink**: `src/securibench/micro/basic/Basic19.java:52` (`e.printStackTrace(Undefined-e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #9 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl4.java:56` (`e`)
- **Sink**: `src/securibench/micro/pred/Pred8.java:43` (`error.try-2(BasicBlock-b-29)`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #10 检测 Java SQL 语句拼接漏洞

- **Rule ID**: `21d79f98-a435-4c84-81be-055ac21b94ef`
- **Source**: `src/securibench/micro/basic/Basic19.java:45` (`parameter[1].getParameter(Parameter-req,"name"))`)
- **Sink**: `src/securibench/micro/basic/Basic19.java:45` (`parameter[1].getParameter(Parameter-req,"name"))`)
- **Reason**: SQL拼接规则在SQLi项目中触发，但源/汇点与测试用例期望位置不匹配，可能是规则覆盖范围过宽或匹配精度不足。

### #11 检测Java泛型异常捕获

- **Rule ID**: `0f9bad23-cac6-4ec9-8509-5c96c2b72175`
- **Source**: `src/securibench/micro/reflection/Refl2.java:46` (`e`)
- **Sink**: `src/securibench/micro/reflection/Refl2.java:46` (`e`)
- **Reason**: 泛型异常捕获规则与项目目标漏洞类型无关。

### #12 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/sanitizers/Sanitizers5.java:43` (`con.createStatement)`)
- **Sink**: `src/securibench/micro/basic/Basic20.java:44` (`handler`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #13 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/basic/Basic21.java:60` (`e.printStackTrace(Undefined-e)`)
- **Sink**: `src/securibench/micro/basic/Basic21.java:60` (`e.printStackTrace(Undefined-e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #14 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/basic/Basic19.java:46` (`e`)
- **Sink**: `src/securibench/micro/basic/Basic19.java:43` (`handler`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #15 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/inter/Inter13.java:51` (`e.printStackTrace(Parameter-resp)`)
- **Sink**: `src/securibench/micro/inter/Inter13.java:51` (`e.printStackTrace(Parameter-resp)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #16 检测Java java.sql Statement查询结果集ResultSet资源未释放

- **Rule ID**: `4dc8d2a1-6cca-4025-a219-7c52ac3a5fd7`
- **Source**: `src/securibench/micro/basic/Basic21.java:53` (`stmt.executeQuery(Undefined-con.createStatement(Undefined-DriverManager.getConnection(DriverManager,Undefined-MicroTestCase.CONNECTION_STRING(valid))),add(Function-Basic29.getVulnerabilityCount, Undefined-s.toLowerCase(ParameterMember-parameter[1].getParameter(Parameter-req,ParameterMember-parameter[1].getParameter),Function-Basic3.getVulnerabilityCount)))`)
- **Sink**: `src/securibench/micro/basic/Basic21.java:53` (`stmt.executeQuery(Undefined-con.createStatement(Undefined-DriverManager.getConnection(DriverManager,Undefined-MicroTestCase.CONNECTION_STRING(valid))),add(Function-Basic29.getVulnerabilityCount, Undefined-s.toLowerCase(ParameterMember-parameter[1].getParameter(Parameter-req,ParameterMember-parameter[1].getParameter),Function-Basic3.getVulnerabilityCount)))`)
- **Reason**: 资源泄漏规则检测JDBC资源未释放，与项目目标漏洞类型无关。

### #17 检测 Java SQL 语句拼接漏洞

- **Rule ID**: `21d79f98-a435-4c84-81be-055ac21b94ef`
- **Source**: `src/securibench/micro/basic/Basic21.java:49` (`s.toLowerCase(ParameterMember-parameter[1].getParameter(Parameter-req,ParameterMember-parameter[1].getParameter),Function-Basic3.getVulnerabilityCount))`)
- **Sink**: `src/securibench/micro/basic/Basic21.java:49` (`s.toLowerCase(ParameterMember-parameter[1].getParameter(Parameter-req,ParameterMember-parameter[1].getParameter),Function-Basic3.getVulnerabilityCount))`)
- **Reason**: SQL拼接规则在SQLi项目中触发，但源/汇点与测试用例期望位置不匹配，可能是规则覆盖范围过宽或匹配精度不足。

### #18 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/reflection/Refl1.java:62` (`e)`)
- **Sink**: `src/securibench/micro/reflection/Refl1.java:62` (`e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #19 检测Java java.sql 数据库Statement资源未释放

- **Rule ID**: `195768f2-de1d-4e9f-9a72-7244efbc0abf`
- **Source**: `src/securibench/micro/basic/Basic19.java:45` (`con.prepareStatement(Undefined-DriverManager.getConnection(DriverManager,Undefined-MicroTestCase.CONNECTION_STRING(valid)),add("select * from Users where name=", ParameterMember-parameter[1].getParameter(Parameter-req,"name")))`)
- **Sink**: `src/securibench/micro/basic/Basic19.java:45` (`con.prepareStatement(Undefined-DriverManager.getConnection(DriverManager,Undefined-MicroTestCase.CONNECTION_STRING(valid)),add("select * from Users where name=", ParameterMember-parameter[1].getParameter(Parameter-req,"name")))`)
- **Reason**: 资源泄漏规则检测JDBC资源未释放，与项目目标漏洞类型无关。

### #20 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/basic/Basic20.java:54` (`e.printStackTrace(Undefined-e)`)
- **Sink**: `src/securibench/micro/basic/Basic20.java:54` (`e.printStackTrace(Undefined-e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #21 检测 Java SQL 语句拼接漏洞

- **Rule ID**: `21d79f98-a435-4c84-81be-055ac21b94ef`
- **Source**: `src/securibench/micro/basic/Basic21.java:50` (`s.toLowerCase(ParameterMember-parameter[1].getParameter(Parameter-req,ParameterMember-parameter[1].getParameter),Function-Basic3.getVulnerabilityCount))`)
- **Sink**: `src/securibench/micro/basic/Basic21.java:50` (`s.toLowerCase(ParameterMember-parameter[1].getParameter(Parameter-req,ParameterMember-parameter[1].getParameter),Function-Basic3.getVulnerabilityCount))`)
- **Reason**: SQL拼接规则在SQLi项目中触发，但源/汇点与测试用例期望位置不匹配，可能是规则覆盖范围过宽或匹配精度不足。

### #22 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/reflection/Refl1.java:64` (`e)`)
- **Sink**: `src/securibench/micro/reflection/Refl1.java:64` (`e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #23 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/basic/Basic21.java:54` (`e`)
- **Sink**: `src/securibench/micro/basic/Basic21.java:46` (`handler`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #24 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl3.java:59` (`e`)
- **Sink**: `src/securibench/micro/pred/Pred5.java:43` (`b-10],BasicBlock-b-1]`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

## Analysis Notes

项目 securibench-micro-sqli 共产生 25 个误报，6 个漏报。主要误报来源：检测Java空Catch块（10次）。当前扫描结果以误报为主，且存在大量漏报，说明规则集与测试项目不匹配或规则精度不足。

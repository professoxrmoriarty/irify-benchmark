# False Positive Analysis Report

- **Project**: `securibench-micro-xss` (Securibench Micro XSS)
- **Engine**: yaklang 1.4.7-beta1
- **Total Cases**: 124
- **Results**: TP=0 / FN=124 / FP=24 / TN=0
- **Total Findings**: 24

## Missing Rules

- 缺少Java XSS检测规则（yaklang buildin中无Java XSS规则）

## Rule Summary (False Positive Distribution)

| Rule Name | Count | Severity | Suggested Action |
|-----------|-------|----------|------------------|
| 检测Java空Catch块 | 10 | low | 在benchmark扫描时排除此规则，或增加lang/opcode过滤限制其在Servlet/Web上下文中的触发。 |
| 检查Java通过PrintStackTrace泄露信息 | 6 | low | 在benchmark扫描时排除此规则，或增加调用上下文限制（如仅在HTTP响应处理链中触发）。 |
| 检测Java Lang库未检查返回值的API | 5 | info | 此规则为info级别代码质量规则，建议在安全benchmark中直接排除。 |
| 检测 Java SQL 语句拼接漏洞 | 3 | middle | 在非SQLi项目中排除此规则。 |

## False Positive Details

### #0 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl4.java:54` (`e`)
- **Sink**: `src/securibench/micro/reflection/Refl4.java:51` (`handler`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #1 检测Java Lang库未检查返回值的API

- **Rule ID**: `11d8d5f5-900b-4d88-82f7-88f8b3c67fcd`
- **Source**: `src/securibench/micro/basic/Basic1.java:39` (`writer.println(Undefined-b3.toString,ParameterMember-parameter[1].getParameter(<nil:8649>,"name"))`)
- **Sink**: `src/securibench/micro/basic/Basic1.java:39` (`writer.println(Undefined-b3.toString,ParameterMember-parameter[1].getParameter(<nil:8649>,"name"))`)
- **Reason**: 该规则检测String/Runtime等返回值未使用，属于代码质量规则，与项目安全漏洞测试目标无关。

### #2 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/reflection/Refl1.java:60` (`e)`)
- **Sink**: `src/securibench/micro/reflection/Refl1.java:60` (`e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #3 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/basic/Basic19.java:52` (`e)`)
- **Sink**: `src/securibench/micro/basic/Basic19.java:52` (`e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #4 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl4.java:56` (`e`)
- **Sink**: `src/securibench/micro/reflection/Refl4.java:51` (`handler`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #5 检测Java Lang库未检查返回值的API

- **Rule ID**: `11d8d5f5-900b-4d88-82f7-88f8b3c67fcd`
- **Source**: `src/securibench/micro/basic/Basic27.java:45` (`this(ParameterMember-parameter[2].getWriter(Parameter-resp),Undefined-s3.replace)`)
- **Sink**: `src/securibench/micro/basic/Basic27.java:45` (`this(ParameterMember-parameter[2].getWriter(Parameter-resp),Undefined-s3.replace)`)
- **Reason**: 该规则检测String/Runtime等返回值未使用，属于代码质量规则，与项目安全漏洞测试目标无关。

### #6 检测Java Lang库未检查返回值的API

- **Rule ID**: `11d8d5f5-900b-4d88-82f7-88f8b3c67fcd`
- **Source**: `src/securibench/micro/basic/Basic25.java:43` (`o2.toString,BasicBlock-defer-3)`)
- **Sink**: `src/securibench/micro/basic/Basic25.java:43` (`o2.toString,BasicBlock-defer-3)`)
- **Reason**: 该规则检测String/Runtime等返回值未使用，属于代码质量规则，与项目安全漏洞测试目标无关。

### #7 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl3.java:59` (`e`)
- **Sink**: `src/securibench/micro/reflection/Refl3.java:48` (`catch(Undefined-e)`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #8 检测 Java SQL 语句拼接漏洞

- **Rule ID**: `21d79f98-a435-4c84-81be-055ac21b94ef`
- **Source**: `src/securibench/micro/basic/Basic19.java:45` (`parameter[1].getParameter("doGet",Function-Arrays3.getDescription))`)
- **Sink**: `src/securibench/micro/basic/Basic19.java:45` (`parameter[1].getParameter("doGet",Function-Arrays3.getDescription))`)
- **Reason**: SQL相关规则在非SQLi测试项目中触发，属于跨类型误报。

### #9 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl1.java:62` (`e.printStackTrace`)
- **Sink**: `src/securibench/micro/reflection/Refl1.java:42` (`parameter[2].error.try-2: <-  (<nil condition>)`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #10 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/basic/Basic16.java:62` (`Basic16.getVulnerabilityCount`)
- **Sink**: `src/securibench/micro/basic/Basic16.java:36` (`contents`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #11 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/inter/Inter13.java:51` (`resp)`)
- **Sink**: `src/securibench/micro/inter/Inter13.java:51` (`resp)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #12 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/reflection/Refl1.java:62` (`e)`)
- **Sink**: `src/securibench/micro/reflection/Refl1.java:62` (`e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #13 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl3.java:73` (`1`)
- **Sink**: `src/securibench/micro/reflection/Refl3.java:48` (`handler`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #14 检测Java Lang库未检查返回值的API

- **Rule ID**: `11d8d5f5-900b-4d88-82f7-88f8b3c67fcd`
- **Source**: `src/securibench/micro/collections/Collections10.java:54` (`writer.println(ParameterMember-parameter[1].parameter[2].<nil key:4375>,"getWriter")`)
- **Sink**: `src/securibench/micro/collections/Collections10.java:54` (`writer.println(ParameterMember-parameter[1].parameter[2].<nil key:4375>,"getWriter")`)
- **Reason**: 该规则检测String/Runtime等返回值未使用，属于代码质量规则，与项目安全漏洞测试目标无关。

### #15 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl3.java:44` (`b-4`)
- **Sink**: `src/securibench/micro/reflection/Refl3.java:48` (`handler`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #16 检测 Java SQL 语句拼接漏洞

- **Rule ID**: `21d79f98-a435-4c84-81be-055ac21b94ef`
- **Source**: `src/securibench/micro/basic/Basic21.java:53` (`s.toLowerCase(ParameterMember-parameter[1].getParameter(BasicBlock-entry-0,ParameterMember-parameter[1].getParameter),Function-Basic3.getVulnerabilityCount))`)
- **Sink**: `src/securibench/micro/basic/Basic21.java:53` (`s.toLowerCase(ParameterMember-parameter[1].getParameter(BasicBlock-entry-0,ParameterMember-parameter[1].getParameter),Function-Basic3.getVulnerabilityCount))`)
- **Reason**: SQL相关规则在非SQLi测试项目中触发，属于跨类型误报。

### #17 检测 Java SQL 语句拼接漏洞

- **Rule ID**: `21d79f98-a435-4c84-81be-055ac21b94ef`
- **Source**: `src/securibench/micro/basic/Basic21.java:50` (`s.toLowerCase(ParameterMember-parameter[1].getParameter(BasicBlock-entry-0,ParameterMember-parameter[1].getParameter),Function-Basic3.getVulnerabilityCount))`)
- **Sink**: `src/securibench/micro/basic/Basic11.java:47` (`"getDescription"`)
- **Reason**: SQL相关规则在非SQLi测试项目中触发，属于跨类型误报。

### #18 检测Java Lang库未检查返回值的API

- **Rule ID**: `11d8d5f5-900b-4d88-82f7-88f8b3c67fcd`
- **Source**: `src/securibench/micro/collections/Collections10.java:61` (`writer.println(ParameterMember-parameter[1].parameter[2].<nil key:4375>,Undefined-iter.next(Undefined-c2.iterator(Parameter-this(Undefined-ArrayList))))`)
- **Sink**: `src/securibench/micro/collections/Collections10.java:61` (`writer.println(ParameterMember-parameter[1].parameter[2].<nil key:4375>,Undefined-iter.next(Undefined-c2.iterator(Parameter-this(Undefined-ArrayList))))`)
- **Reason**: 该规则检测String/Runtime等返回值未使用，属于代码质量规则，与项目安全漏洞测试目标无关。

### #19 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl3.java:50` (`clazz.newInstance`)
- **Sink**: `src/securibench/micro/reflection/Refl3.java:48` (`handler`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #20 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/reflection/Refl1.java:64` (`e)`)
- **Sink**: `src/securibench/micro/reflection/Refl1.java:64` (`e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #21 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/basic/Basic21.java:60` (`Basic36.getVulnerabilityCount(Undefined-e)`)
- **Sink**: `src/securibench/micro/basic/Basic21.java:60` (`Basic36.getVulnerabilityCount(Undefined-e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #22 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl3.java:45` (`parameter[1].getParameter`)
- **Sink**: `src/securibench/micro/reflection/Refl3.java:48` (`handler`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #23 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl1.java:60` (`e.printStackTrace`)
- **Sink**: `src/securibench/micro/reflection/Refl1.java:60` (`e.printStackTrace`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

## Analysis Notes

项目 securibench-micro-xss 共产生 24 个误报，124 个漏报。主要误报来源：检测Java空Catch块（10次）。当前扫描结果以误报为主，且存在大量漏报，说明规则集与测试项目不匹配或规则精度不足。

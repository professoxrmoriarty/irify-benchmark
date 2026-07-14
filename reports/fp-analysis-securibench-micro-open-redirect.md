# False Positive Analysis Report

- **Project**: `securibench-micro-open-redirect` (Securibench Micro Open Redirect)
- **Engine**: yaklang 1.4.7-beta1
- **Total Cases**: 2
- **Results**: TP=0 / FN=2 / FP=19 / TN=0
- **Total Findings**: 19

## Missing Rules

- 缺少Java Open Redirect检测规则（现有java-direct-url-redirect.sf未在本项目触发）

## Rule Summary (False Positive Distribution)

| Rule Name | Count | Severity | Suggested Action |
|-----------|-------|----------|------------------|
| 检测Java空Catch块 | 9 | low | 在benchmark扫描时排除此规则，或增加lang/opcode过滤限制其在Servlet/Web上下文中的触发。 |
| 检查Java通过PrintStackTrace泄露信息 | 7 | low | 在benchmark扫描时排除此规则，或增加调用上下文限制（如仅在HTTP响应处理链中触发）。 |
| 检测 Java SQL 语句拼接漏洞 | 1 | middle | 在非SQLi项目中排除此规则。 |
| 检测Java Lang库未检查返回值的API | 1 | info | 此规则为info级别代码质量规则，建议在安全benchmark中直接排除。 |
| 检测Java泛型异常捕获 | 1 | low | 代码风格规则，建议benchmark排除。 |

## False Positive Details

### #0 检测 Java SQL 语句拼接漏洞

- **Rule ID**: `21d79f98-a435-4c84-81be-055ac21b94ef`
- **Source**: `src/securibench/micro/basic/Basic21.java:50` (`contents(ParameterMember-parameter[1].getParameter(Function-Arrays7.getDescription,ParameterMember-parameter[1].getParameter),Undefined-Locale.UK))`)
- **Sink**: `src/securibench/micro/basic/Basic21.java:50` (`contents(ParameterMember-parameter[1].getParameter(Function-Arrays7.getDescription,ParameterMember-parameter[1].getParameter),Undefined-Locale.UK))`)
- **Reason**: SQL相关规则在非SQLi测试项目中触发，属于跨类型误报。

### #1 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl3.java:61` (`e`)
- **Sink**: `src/securibench/micro/pred/Pred5.java:43` (`b-10],BasicBlock-b-1]`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #2 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/basic/Basic21.java:60` (`entry-0(Undefined-e)`)
- **Sink**: `src/securibench/micro/basic/Basic21.java:60` (`entry-0(Undefined-e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #3 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/reflection/Refl1.java:62` (`e)`)
- **Sink**: `src/securibench/micro/reflection/Refl1.java:62` (`e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #4 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/BasicTestCase.java:28` (`BasicTestCase.doTrace`)
- **Sink**: `src/securibench/micro/aliasing/Aliasing1.java:48` (`entry-0`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #5 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/basic/Basic20.java:54` (`Basic12.getDescription(Undefined-e)`)
- **Sink**: `src/securibench/micro/basic/Basic20.java:54` (`Basic12.getDescription(Undefined-e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #6 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl2.java:46` (`e`)
- **Sink**: `src/securibench/micro/pred/Pred4.java:43` (`3`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #7 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/basic/Basic19.java:52` (`Basic39.getVulnerabilityCount(Undefined-e)`)
- **Sink**: `src/securibench/micro/basic/Basic39.java:51` (`Basic39.getVulnerabilityCount`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #8 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/reflection/Refl1.java:60` (`e)`)
- **Sink**: `src/securibench/micro/reflection/Refl1.java:60` (`e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #9 检测Java Lang库未检查返回值的API

- **Rule ID**: `11d8d5f5-900b-4d88-82f7-88f8b3c67fcd`
- **Source**: `src/securibench/micro/basic/Basic27.java:45` (`writer.println(ParameterMember-parameter[2].getWriter(Parameter-resp),Undefined-s3.replace)`)
- **Sink**: `src/securibench/micro/basic/Basic6.java:39` (`s3.replace`)
- **Reason**: 该规则检测String/Runtime等返回值未使用，属于代码质量规则，与项目安全漏洞测试目标无关。

### #10 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl4.java:56` (`e`)
- **Sink**: `src/securibench/micro/pred/Pred8.java:43` (`error.try-2(BasicBlock-b-29)`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #11 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/basic/Basic19.java:46` (`e`)
- **Sink**: `src/securibench/micro/basic/Basic25.java:50` (`"getVulnerabilityCount"`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #12 检测Java泛型异常捕获

- **Rule ID**: `0f9bad23-cac6-4ec9-8509-5c96c2b72175`
- **Source**: `src/securibench/micro/reflection/Refl2.java:46` (`e`)
- **Sink**: `src/securibench/micro/reflection/Refl2.java:46` (`e`)
- **Reason**: 泛型异常捕获规则与项目目标漏洞类型无关。

### #13 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/pred/Pred5.java:53` (`this`)
- **Sink**: `src/securibench/micro/pred/Pred8.java:43` (`error.try-2(BasicBlock-b-29)`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #14 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/inter/Inter13.java:51` (`e.printStackTrace(Parameter-resp)`)
- **Sink**: `src/securibench/micro/inter/Inter13.java:51` (`e.printStackTrace(Parameter-resp)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #15 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl3.java:59` (`e`)
- **Sink**: `src/securibench/micro/pred/Pred5.java:43` (`b-10],BasicBlock-b-1]`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #16 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl3.java:57` (`e`)
- **Sink**: `src/securibench/micro/pred/Pred5.java:43` (`b-10],BasicBlock-b-1]`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

### #17 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/reflection/Refl1.java:64` (`e)`)
- **Sink**: `src/securibench/micro/reflection/Refl1.java:64` (`e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #18 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/reflection/Refl3.java:63` (`e`)
- **Sink**: `src/securibench/micro/pred/Pred5.java:43` (`b-10],BasicBlock-b-1]`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

## Analysis Notes

项目 securibench-micro-open-redirect 共产生 19 个误报，2 个漏报。主要误报来源：检测Java空Catch块（9次）。当前扫描结果以误报为主，且存在大量漏报，说明规则集与测试项目不匹配或规则精度不足。

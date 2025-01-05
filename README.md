# NetSec-Auto

> In the modern digital era, the surge of connected devices has made network security more intricate than ever. Each new device introduced to a network can be a potential entry point for cyber threats, putting valuable assets and sensitive information at risk. Understanding the situation’s urgency, TitanTech Solutions—a global leader in technology and innovation—seeks to strengthen its security defences with a cutting edge, automated network protection platform.
>
> As the newly appointed Network Security Automation Engineer, you are entrusted with developing an all-encompassing solution capable of continuous monitoring, threat detection, and customised reporting. Your mission is to design a versatile platform that fortifies the network against vulnerabilities and provides actionable insights through detailed, automated reports. It’s time to leverage your expertise to build a dynamic system that meets TitanTech Solutions’ rigorous security standards and safeguards its digital infrastructure against evolving threats.

------



**Part 1: Network Vulnerability Monitoring (15 marks)**

Network vulnerability monitoring plays a critical role in the network security pipeline. An automated approach to monitor network vulnerabilities allows a more efficient and rapid security response, such as patching and implementing appropriate policies. Your tasks are:

* Monitor the network using network sniffers or port scanners to detect network services (5 marks)
* Detect vulnerabilities based on network services or web technologies in use. You may use tools like Shodan.io to assist with the process (5 marks)
*  Based on the vulnerabilities detected, perform an automated search for corresponding exploits, if available (5 marks)



**Part 2: Intelligent Bot or Automation (15 marks)**

The company is interested in exploring the latest technology, LLM-based bots. The company wants you to build a bot (chatbot, telegram bot or related). The bot shall be able to interpret the vulnerabilities found in Part 1. For example, when prompted *What* *is the highest vulnerability in my network?* the bot should be able to return an appropriate response. Your tasks are:

* Build a knowledge base for the Bot (5 marks)
* Build the Bot pipeline (i.e., prompts and responses) (5 marks)
*  Link the knowledge base to the Bot pipeline (5 marks)

You can explore solutions like BotPress, RASA Bot, LLamaIndex and/or OpenAI to help you get started.

**Alternatively**, build an automation pipeline where you will receive an email/telegram notification if any vulnerabilities are detected on your network.

* Build the customised report containing appropriate information (e.g., vulnerability type, endpoint address) for the automated notification (2 marks)

* Build the automated notification method using SMTP for email or webhooks for Telegram (10 marks)

* Connect the automation pipeline to ensure notifications are sent correctly and promptly when vulnerabilities are detected (3 marks)

  

**Part 3: Network Analytics (10 marks)**

Previous sections have generated a lot of information - and there is no better way to 

handle them than to perform quick network analytics. Your tasks are:

* Generate appropriate statistics based on findings from Part 1 and/or 2 (5 marks)
*  Map the statistics to appropriate visualisations (5 marks)





#### TODOLIST

* 数据同步到BOT上
* 漏洞数据SQL
* 数据展示
* 邮件配置
* 定时任务
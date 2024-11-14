package output

import (
	"encoding/json"
	"fmt"
	"os"
	data "recon/pkg/data/type"
	"regexp"
	"strings"
)

func FileJson() {
	// Convert ListDomain to JSON and write to file
	file, err := os.Create("list_domain.json")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Set indentation for readability
	err = encoder.Encode(data.ListDomain)
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
	}
}

func escapeSpecialCharacters(text string) string {
	// List of special characters that need to be escaped in LaTeX
	specialCharacters := []string{"\\", "_", "#", "$", "%", "&", "{", "}", "~", "^"}

	// Loop through each special character and replace it with \<character>
	for _, char := range specialCharacters {
		// Create a regular expression to replace special characters
		re := regexp.MustCompile(fmt.Sprintf("(%s)", regexp.QuoteMeta(char)))
		// Add a \ sign before special characters
		text = re.ReplaceAllString(text, `\`+char)
	}

	return text
}

func ReportLatex(workDirectory string, infoDomain data.InfoDomain) {
	header :=
		`\documentclass[a4paper,12pt]{article}
\usepackage{float}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage[vietnamese]{babel}
\usepackage{graphicx}
\usepackage{enumitem}
\setlist[itemize]{left=5pt}
\usepackage{tikz}
\usepackage{xurl} 
\usepackage{eso-pic}
\usepackage[round]{natbib}
\usepackage{listings}
\usepackage{color}
\usepackage{verbatimbox}
\usepackage{caption}
\usepackage{pdflscape}
\usepackage{changepage}
\usepackage[letterpaper,top=2cm,bottom=2cm,left=3cm,right=3cm,marginparwidth=1.75cm]{geometry}
\usepackage{amsmath}
\usepackage[colorlinks=true, allcolors=black]{hyperref}
\usepackage{amsfonts} 
\usepackage{amssymb}   
\usepackage{longtable} 
\usepackage{fancyhdr}  
\usepackage{minted}

\title{Báo cáo Reconnaissance}
\author{Tên bạn}
\date{\today}

\begin{document}

\maketitle

\tableofcontents
\newpage

\section{Giới thiệu}

Báo cáo này cung cấp một cái nhìn toàn diện về hoạt động thăm dò hệ thống
của mục tiêu. Thông tin được thu thập bao gồm tên miền, địa chỉ IP, thông tin
các cổng, công nghệ sử dụng, bản ghi CNAME, lỗ hổng bảo mật, các đường dẫn,
thư mục, file. Báo cáo này được chuẩn bị nhằm hỗ trợ các đánh giá và lập kế
hoạch bảo mật nội bộ.

\section{Thông tin về mục tiêu}
`

	DNSRecordInformation := fmt.Sprintf(
		`\section{Thông tin về DNS Record}
\begin{itemize} 
\item MX Records:
\begin{minted}[fontsize=\footnotesize, linenos, breaklines, breakanywhere=true]{json}
"%s"
\end{minted}
\item NS Records:
\begin{minted}[fontsize=\footnotesize, linenos, breaklines, breakanywhere=true]{json}
"%s"
\end{minted}
\item SOA Records:
\begin{minted}[fontsize=\footnotesize, linenos, breaklines, breakanywhere=true]{json}
"%s"
\end{minted}
\item TXT Records:
\begin{minted}[fontsize=\footnotesize, linenos, breaklines, breakanywhere=true]{json}
"%s"
\end{minted}
\end{itemize}`, strings.Join(infoDomain.MXRecords, "\n"),
		strings.Join(infoDomain.NSRecords, "\n"),
		strings.Join(infoDomain.SOARecords, "\n"),
		strings.Join(infoDomain.TXTRecords, "\n"),
	)

	var SubdomainInformationSingle string
	var TechInformationOfSingleDomain string
	var VulnInformationOfSingleDomain string

	for _, InfoSubDomain := range infoDomain.SubDomain {
		var Ips string
		var PortsAndServices string
		var Os string
		var CName string
		var HTTP string
		var Status string
		var Title string
		var InformationOfTech string

		Ips = strings.Join(InfoSubDomain.Ips, "\n\n")
		for _, PortsAndService := range InfoSubDomain.PortAndService {
			PortsAndServices += PortsAndService + "\n\n"
		}
		Os = strings.Join(InfoSubDomain.Os, "\n\n")
		CName = strings.Join(InfoSubDomain.CName, "\n\n")
		for Http, Web := range InfoSubDomain.Web {
			HTTP = Http
			Status = Web.Status
			Title = Web.Title
			for TechName, TechInfo := range Web.TechnologyDetails {
				InformationOfTech += fmt.Sprintf(
					`\item %s:
					\begin{itemize} 
					\item Description: %s
					\item Website: %s
					\item CPE: %s
					\item Categories: %s
					\end{itemize}
					`, TechName, TechInfo.Description, TechInfo.Website, escapeSpecialCharacters(TechInfo.CPE), strings.Join(TechInfo.Categories, "\n"),
				)
			}
		}

		SubdomainInformationSingle += fmt.Sprintf(
			`\item Tên SubDomain: %s
				\begin{itemize} 
				\item IPs: 
				
				%s
				\item Port and Service: 

				%s
				\item OS:

				%s
				\item CNAME: 
				
				%s
				\item HTTP/HTTPS: %s
				\item STATUS: %s
				\item TITLE: %s
				\end{itemize}
				`, InfoSubDomain.NameSubDomain, Ips, PortsAndServices, escapeSpecialCharacters(Os), CName, HTTP, Status, Title,
		)

		TechInformationOfSingleDomain += fmt.Sprintf(
			`\item Tên SubDomain: %s
				\begin{itemize} 
				%s
				\end{itemize}
				`, InfoSubDomain.NameSubDomain, InformationOfTech,
		)
	}

	for DomainName, InforVulnerability := range infoDomain.Vulnerability {
		var InformationOfVuln string
		for _, InforVulnerabilitySingle := range InforVulnerability {
			InformationOfVuln += fmt.Sprintf(
				`\item TemplateID: %s
				\begin{itemize} 
				\item Type: %s          
				\item Severity: %s            
				\item Extractor Name: %s      
				\item Matcher Name: %s  
				\item Matched: \url{%s}   
				\item Template Name: %s        
				\item Template Description: %s 
				\item Extracted Results: %s 
				\item Classification: \url{%s}   
				\end{itemize}
				`,
				escapeSpecialCharacters(InforVulnerabilitySingle.TemplateID),
				escapeSpecialCharacters(InforVulnerabilitySingle.Type),
				escapeSpecialCharacters(InforVulnerabilitySingle.Severity),
				escapeSpecialCharacters(InforVulnerabilitySingle.ExtractorName),
				escapeSpecialCharacters(InforVulnerabilitySingle.MatcherName),
				escapeSpecialCharacters(InforVulnerabilitySingle.Matched),
				escapeSpecialCharacters(InforVulnerabilitySingle.TemplateName),
				escapeSpecialCharacters(InforVulnerabilitySingle.TemplateDescription),
				escapeSpecialCharacters(strings.Join(InforVulnerabilitySingle.ExtractedResults, "\n")),
				escapeSpecialCharacters(InforVulnerabilitySingle.Classification),
			)
		}

		VulnInformationOfSingleDomain += fmt.Sprintf(
			`\item Tên SubDomain: %s
				\begin{itemize} 
				%s
				\end{itemize}
				`, DomainName, InformationOfVuln,
		)
	}

	SubdomainInformation := fmt.Sprintf(
		`\section{Thông tin về Sub Domain}
			\begin{itemize} 
				%s
			\end{itemize}
			`, SubdomainInformationSingle)

	TechnologyInformation := fmt.Sprintf(
		`\section{Thông tin về các Công nghệ được sử dụng}
			\begin{itemize} 
				%s
			\end{itemize}
			`, TechInformationOfSingleDomain)

	VulnerabilityInformation := fmt.Sprintf(
		`\section{Thông tin về Lỗ hổng bảo mật}
			\begin{itemize} 
				%s
			\end{itemize}
			`, VulnInformationOfSingleDomain)

	footer :=
		`\section{Thông tin về Link, Thư mục và File}

		Do kết quả quá nhiều không hiển thị vào báo cáo.
		
		\newpage

	\section{Kết luận}
	Qua quá trình thăm dò, chúng tôi đã phát hiện nhiều lỗ hổng bảo mật nghiêm trọng trên hệ thống mục tiêu. Đề nghị đội ngũ bảo mật triển khai các biện pháp khắc phục ngay lập tức, bao gồm vá lỗi SQL Injection, bảo vệ cổng SSH, và kiểm tra bảo mật XSS trên tất cả các form nhập liệu.

	\section{Phụ lục}
	\subsection{Danh sách công cụ sử dụng}
	\begin{itemize} 
		\item Domain OSINT Amass: Thu thập tên miền phụ bằng Amass.
		\item Domain BruteForce Over DNS: Thu thập tên miền phụ bằng cách sử dụng vũ lực trên dns và sử dụng danh sách từ https://github.com/danielmiessler/SecLists trong dữ liệu thư mục data/input.
		\item Domain OSINT Subfinder: Thu thập tên miền phụ bằng Subfinder.
		\item Domain BruteForce Over Http: Thu thập tên miền phụ bằng cách sử dụng vũ lực trên http và sử dụng danh sách từ https://github.com/danielmiessler/SecLists trong dữ liệu thư mục/đầu vào. Như bạn đã biết, một số tên miền phụ không được công khai trên máy chủ dns. Nó đã được truy cập qua tiêu đề đã chỉnh sửa. Tên miền phụ này có thể là riêng tư hoặc vẫn đang trong quá trình thử nghiệm.
		\item Collect all domain information: Thu thập IP, CNAME, PORT, SERVICE, OS, LINK, TECH, STATUS, TITLE, VULNERABILITY của Subdomain. Nó sử dụng Nmap, Naabu, Waybackurls, Wappalyzergo, Nuclei...
	\end{itemize}

	\subsection{Liên hệ}
	Để biết thêm thông tin chi tiết về báo cáo, vui lòng liên hệ:
	\begin{itemize} 
		\item Email: \href{mailto:email@example.com}{email@example.com}
		\item Website: \href{http://example.com}{www.example.com}
	\end{itemize}

	\end{document}`

	FileReport := header + DNSRecordInformation + SubdomainInformation + TechnologyInformation + VulnerabilityInformation + footer
	file, err := os.Create("report.tex")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	// Ghi nội dung vào file
	_, err = file.WriteString(FileReport)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
}

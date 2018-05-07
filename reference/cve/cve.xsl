<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:template match="/">
	<html>
		<head>
			<title>
				<xsl:value-of select="item/@name" />
			</title>
			<style type='text/css'>
				body {
					font-family: Arial, Helvetica, Calibri, sans-serif;
				}
				.previewHeader {
					vertical-align: middle;
					text-align: center;
					text-decoration: underline;
					font-size: 17px;
					font-weight: bolder;
					margin: 20px;
				}
				.mainSection tr th {
					text-align: left;
					vertical-align: top;
					width: 180px;
					padding: 8px 0px;
				}
				.mainSection tr td {
					padding: 8px 0px;
				}
				.previewLabel {
					font-weight:bold;
					color:black;
				}
				.previewLabelUndln {
					font-weight:bold;
					color:black;
					text-decoration:underline;
					font-style:italic;
				}
			</style>
		</head>
		<body>
			<span style="font-weight:bolder;">Description:</span><br />
			<xsl:value-of select="item/desc" /><br />
			<table>
				<thead><tr><th>Source</th><th>Title</th></tr></thead>
				<tbody>
				<xsl:for-each select="item/refs/ref">
					<tr><td><xsl:value-of select="@source"/></td><td><a href="{@url}"><xsl:value-of select="." /></a></td></tr>
				</xsl:for-each>
				</tbody>
			</table>
		</body>
	</html>
	</xsl:template>
</xsl:stylesheet>
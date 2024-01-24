module Issue::Linker
  # {
  #   "ok": true,
  #   "next_page": "https://api.shiftleft.io/orgs/4c07962d-745f-4465-9965-002f6cf3c7ff/findings?page=2",
  #   "response": {
  #     "has_more": true,
  #     "scan": {
  #       # Scan Data
  #     },
  #     "findings": [
  #       # Array of ShiftLeftIssue
  #     ],
  #     "counts": [
  #       # Array of totals, irrelevant to us
  #     ]
  #   }
  # }
  struct ShiftLeftResponse
    include JSON::Serializable
    getter ok : Bool
    getter next_page : String?
    getter response : Response

    struct Response
      include JSON::Serializable
      getter has_more : Bool?
      getter findings : Array(ShiftLeftIssue)
    end
  end

  # We get our data like this:
  # {
  #       "id": "2759",
  #       "app": "brokencrystals",
  #       "type": "vuln",
  #       "title": "XML External Entities: Attacker-controlled Data Parsed as XML via `xml` in `app.controller.ts:xml`",
  #       "description": "Attacker-controlled data is parsed as XML.",
  #       "internal_id": "xxe-injection-attacker/f6b5560d469f42a5750972b4fd8a7f93/69247c3b2bc226d3953c196a67a6fe94cfb590f6f843d5a2a686f3afa2c7dbb5",
  #       "severity": "critical",
  #       "owasp_category": "a4-xxe",
  #       "category": "XML External Entities",
  #       "version_first_seen": "10214a2198b82e82c2b36a14ee80fc1b5c3d6d9ca00ed705fb9e90658b733c99",
  #       "scan_first_seen": "4",
  #       "created_at": "2024-01-18T15:59:48.351355Z",
  #       "details": {
  #         "Link": "https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A4-XML_External_Entities_(XXE)",
  #         "name": "xxe-injection-attacker",
  #         "tags": "",
  #         "ml_assisted": "false",
  #         "sink_method": "^libxmljs^.parseXml",
  #         "source_method": "src/app.controller.ts::program:xml",
  #         "file_locations": [
  #           "src/app.controller.ts:103",
  #           "src/app.controller.ts:104"
  #         ]
  #       },
  #       "tags": [
  #         {
  #           "key": "category",
  #           "value": "XML External Entities"
  #         },
  #         {
  #           "key": "cvss_31_severity_rating",
  #           "value": "critical"
  #         },
  #         {
  #           "key": "cvss_score",
  #           "value": "9"
  #         },
  #         {
  #           "key": "cwe_category",
  #           "value": "611"
  #         },
  #         {
  #           "key": "cwe_category",
  #           "value": "91"
  #         },
  #         {
  #           "key": "language",
  #           "value": "javascript"
  #         },
  #         {
  #           "key": "ml_assisted",
  #           "value": "false"
  #         },
  #         {
  #           "key": "owasp_2021_category",
  #           "value": "a05-security-misconfiguration"
  #         },
  #         {
  #           "key": "owasp_category",
  #           "value": "a05-2021-security-misconfiguration"
  #         },
  #         {
  #           "key": "owasp_category",
  #           "value": "a4-xxe"
  #         },
  #         {
  #           "key": "severity",
  #           "value": "critical"
  #         },
  #         {
  #           "key": "sink_method",
  #           "value": "^libxmljs^.parseXml"
  #         },
  #         {
  #           "key": "source_method",
  #           "value": "src/app.controller.ts::program:xml"
  #         }
  #       ],
  #       "related_findings": {},
  #       "risk_score": 2.05
  #     }
  struct ShiftLeftIssue
    include JSON::Serializable

    getter id : String
    getter app : String
    getter type : String
    getter title : String
    getter description : String
    getter internal_id : String
    getter severity : String
    getter details : Details
    getter tags : Array(Tag)

    def cwe : Array(String)
      cwes = Array(String).new
      tags.each do |tag|
        if tag.key == "cwe_category"
          cwes << "CWE-#{tag.value}"
        end
      end
      cwes
    end

    struct Details
      include JSON::Serializable

      getter name : String
      getter tags : String
      getter ml_assisted : String
      getter sink_method : String
      getter source_method : String
      getter file_locations : Array(String)?
    end

    struct Tag
      include JSON::Serializable

      getter key : String
      getter value : String
    end
  end
end

require "json"
require "big"

module Issue::Linker
  struct CXIssueResponse
    include JSON::Serializable
    property results : Array(CXIssue)
  end

  struct CXIssue
    include JSON::Serializable

    @[JSON::Field(key: "queryID", ignore: true, ignore_serialize: true)]
    property query_id : Int32 = 0
    @[JSON::Field(key: "queryName")]
    property query_name : String
    property severity : String
    @[JSON::Field(key: "cweID")]
    property cwe_id : Int32
    @[JSON::Field(key: "similarityID")]
    property similarity_id : Int32
    @[JSON::Field(key: "uniqueID")]
    property unique_id : Int32
    property nodes : Array(Node)
    property group : String
    property compliances : Array(String)
    @[JSON::Field(key: "pathSystemID")]
    property path_system_id : String
    @[JSON::Field(key: "resultHash")]
    property result_hash : String
    @[JSON::Field(key: "languageName")]
    property language_name : String
    @[JSON::Field(key: "firstScanID")]
    property first_scan_id : String
    @[JSON::Field(key: "firstFoundAt")]
    property first_found_at : String
    @[JSON::Field(key: "foundAt")]
    property found_at : String
    property status : String
    property state : String

    struct Node
      include JSON::Serializable

      property column : Int32
      @[JSON::Field(key: "fileName")]
      property file_name : String
      property line : Int32
    end
  end
end

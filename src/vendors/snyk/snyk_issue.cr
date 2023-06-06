require "json"

module Issue::Linker
  struct SnykIssue
    include JSON::Serializable
    getter type : String
    getter id : String
    getter attributes : Attributes

    struct Attributes
      include JSON::Serializable

      getter severity : String
      getter title : String
      getter cwe : Array(String)

      @[JSON::Field(key: "primaryRegion")]
      getter primary_region : PrimaryRegion

      @[JSON::Field(key: "primaryFilePath")]
      getter primary_file_path : String

      getter issue_type : String

      struct PrimaryRegion
        include JSON::Serializable

        @[JSON::Field(key: "endColumn")]
        getter end_column : Int32?
        @[JSON::Field(key: "endLine")]
        getter end_line : Int32?
        @[JSON::Field(key: "startColumn")]
        getter start_column : Int32?
        @[JSON::Field(key: "startLine")]
        getter start_line : Int32?
      end
    end
  end
end

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

      @[JSON::Field(key: "issueType")]
      getter issue_type : String
    end
  end
end

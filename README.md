# EncryptedJsonb

A Ruby gem that provides deterministic encryption for PostgreSQL JSONB columns while preserving structure and enabling encrypted querying.

## Problem

When storing sensitive data in PostgreSQL JSONB columns, you face a dilemma:

- **Store data in plaintext**: Fast queries, but sensitive data is exposed
- **Encrypt the entire JSONB**: Secure, but you lose the ability to query specific nested values

Rails' built-in encryption doesn't work well with complex JSONB structures containing Arrays and Hashes, often failing with encoding errors when trying to encrypt non-string values.

## Solution

EncryptedJsonb solves this by:

1. **Preserving JSONB structure**: arrays and hashes remain as containers
2. **Encrypting only primitive values**: strings, numbers, and booleans are encrypted
3. **Enabling encrypted queries**: Uses deterministic encryption for searchable fields
4. **Avoiding encoding issues**: Properly handles arrays/hashes that don't respond to `#encoding`
5. **Providing tamper detection**: Uses cryptographic signatures to verify data integrity

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'encrypted_jsonb'
```

And then execute:

```bash
bundle install
```

## Usage

### Basic Setup

```ruby
# In your Rails model
class User < ApplicationRecord
  include EncryptedJsonb::Encryptable

  # Encrypt the profile JSONB column
  encrypts_jsonb :profile
end
```

### Configuration

Set up your encryption keys in Rails credentials:

```yaml
# config/credentials.yml.enc
active_record_encryption:
  primary_key: your_32_byte_primary_key
  deterministic_key: your_32_byte_deterministic_key
```

### Example Input/Output

**Original Data:**

```ruby
user_profile = {
  "name" => "John Doe",
  "age" => 30,
  "active" => true,
  "preferences" => {
    "theme" => "dark",
    "notifications" => true
  },
  "tags" => ["admin", "power_user"]
}

user = User.create(profile: user_profile)
```

**Stored in Database (encrypted):**

```json
{
  "message": {
    "name": "{\"p\":\"LceCJ6wqe5A=\",\"h\":{\"iv\":\"MGYcLDwyV6Aa7mHo\",\"at\":\"Bgc74dKlsPwoZiqPxjiNhA==\"}}",
    "age": "{\"p\":\"6wtt9BB3I/lgCw==\",\"h\":{\"iv\":\"EWcq472e3vSHSBbi\",\"at\":\"LHPpBYfSOLJPtBX/W1/pCA==\"}}",
    "active": "{\"p\":\"UEfW35+kNm6p8BuLx2s=\",\"h\":{\"iv\":\"/R6Yo/EkDITBB48a\",\"at\":\"nVCdltRI5iwf3h3VKntWWg==\"}}",
    "preferences": {
      "theme": "{\"p\":\"zRtmBK3AVT0z\",\"h\":{\"iv\":\"FqrSPaxO848jRGD6\",\"at\":\"PP691SehDNEevFnP6wIj4A==\"}}",
      "notifications": "{\"p\":\"ny2w6L7YBQRs\",\"h\":{\"iv\":\"egmwYLwUzDAXXhtp\",\"at\":\"Ja+FbAot3ePp4dypL6WbHg==\"}}"
    },
    "tags": [
      "{\"p\":\"3ZI1gsU=\",\"h\":{\"iv\":\"WofCOkmR3+3wq5eJ\",\"at\":\"OmOQyOnDWWhxD8SQw/BKrA==\"}}",
      "{\"p\":\"Ox0JWQ==\",\"h\":{\"iv\":\"sgzV9QX+5yw1ubYU\",\"at\":\"8eUTEwb1FrFpV6LVqoFpKA==\"}}"
    ]
  },
  "signature": "encrypted_signature_for_tamper_detection"
}
```

**Retrieved Data (automatically decrypted):**

```ruby
user.profile
# Returns the original hash:
# {
#   "name" => "John Doe",
#   "age" => 30,
#   "active" => true,
#   "preferences" => {
#     "theme" => "dark",
#     "notifications" => true
#   },
#   "tags" => ["admin", "power_user"]
# }
```

### Querying Encrypted Data

#### Model-Specific Methods (defined by `encrypts_jsonb`)

```ruby
# These methods are automatically created for each encrypted JSONB column
# For a model with `encrypts_jsonb :profile`, you get:

# Exact path matching
User.where_encrypted_json_path_equals("name", "John Doe")
User.where_encrypted_json_path_equals("preferences.theme", "dark")

# Pattern matching (LIKE queries)
User.where_encrypted_json_path_contains("bio", "engineer")

# Check if path exists
User.where_encrypted_json_path_exists("preferences.notifications")
```

#### Generic Query Helper Methods

```ruby
# Include the QueryHelpers module for more advanced querying
class User < ApplicationRecord
  include EncryptedJsonb::QueryHelpers
end

# Exact value matching at JSON path
User.where_encrypted_jsonb_equals(:profile, ["user", "name"], "John Doe")
User.where_encrypted_jsonb_equals(:profile, ["preferences", "theme"], "dark")

# Hash containment (matches nested structure)
User.where_encrypted_jsonb_contains(:profile, { "user" => { "name" => "John" } })

# Path existence checking
User.where_encrypted_jsonb_exists(:profile, ["user", "preferences"])

# Value in array matching
User.where_encrypted_jsonb_in(:profile, ["user", "role"], ["admin", "moderator"])

# Array contains value
User.where_encrypted_jsonb_array_contains(:profile, ["user", "tags"], "power_user")
```

## Key Features

- **Structure Preservation**: Maintains JSONB structure while encrypting sensitive values
- **Deterministic Encryption**: Same input produces same encrypted output for querying
- **Tamper Detection**: Cryptographic signatures prevent unauthorized modifications
- **Type Safety**: Preserves Ruby data types (Integer, String, Boolean, etc.)
- **Performance Optimized**: Efficient handling of large nested structures
- **Encoding Safe**: Properly handles Arrays/Hashes without encoding issues

## Limitations

- **Query Performance**: Encrypted queries are slower than plaintext queries
- **Nesting Depth**: Limited by Ruby's JSON parsing (≤100 levels deep)
- **Array Size**: Very large arrays (>5000 items) may impact performance
- **Deterministic Only**: Uses deterministic encryption for queryability (less secure than random encryption)

## Security Considerations

- Uses Rails' built-in ActiveRecord encryption
- Deterministic encryption enables querying but reduces security compared to random encryption
- Signatures prevent tampering but don't hide data patterns
- Suitable for applications where queryability is more important than maximum security

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `bundle exec rake test` to run the tests.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/gjtorikian/encrypted_jsonb.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

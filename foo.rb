#!/bin/env ruby
## 

input    = './hype_key'
contents = File.read(input)
tokens   = contents.split(/\s/)

plain = tokens.collect { |t| t.to_i(16).chr }

output = 'hype_key_decoded'
File.open(output, 'w') do |f|
  f.print(plain.join(''))
end


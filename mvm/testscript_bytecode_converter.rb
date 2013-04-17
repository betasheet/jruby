require 'fileutils'
require "pp"

$generate = false

def convert_to_bytecode(file)
  iseq = RubyVM::InstructionSequence.compile_file("testscripts/" + file)
  if $generate
    dumped = Marshal.dump(iseq.to_a)
    bc_file = File.new("testscripts/binarycode/" + file + ".bin", 'w')
    bc_file.write("RBCM")
    bc_file.write(dumped)
    bc_file.close()
  else
    pp iseq.to_a
  end
end

puts "forcing dirs"
FileUtils.mkdir_p("testscripts/binarycode/")

Dir.glob('testscripts/*.rb') do |rb_file|
  puts "converting " + rb_file
  convert_to_bytecode(File.basename(rb_file))
  if not $generate
    break
  end
end
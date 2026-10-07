#!/usr/bin/env ruby
# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/vcdiff"

describe Protocol::HTTP::VCDiff do
	let(:source) {"the quick brown fox"}
	
	it "encodes and restores a representation using source COPY" do
		target = "the quick red fox"
		delta = subject.encode(source, target)
		
		expect(delta).to be(:start_with?, subject::MAGIC)
		expect(subject.decode(source, delta)).to be == target
	end
	
	with "target window COPY" do
		let(:source) {""}
		let(:target) {"abcabcabc"}
		
		it "encodes and restores an overlapping COPY inside the target window" do
			delta = subject.encode(source, target)
			
			expect(delta.bytes).to be(:include?, 46)
			expect(subject.decode(source, delta)).to be == target
		end
	end
	
	it "encodes and restores an empty representation" do
		delta = subject.encode(source, "")
		
		expect(subject.decode(source, delta)).to be == ""
	end
	
	it "rejects secondary compression" do
		delta = subject.encode(source, "other")
		delta = delta.dup
		delta.setbyte(4, subject::VCD_DECOMPRESS)
		
		expect do
			subject.decode(source, delta)
		end.to raise_exception(Protocol::HTTP::VCDiffError, message: be =~ /secondary|Unsupported/)
	end
	
	it "rejects a custom code table" do
		delta = subject.encode(source, "other")
		delta.setbyte(4, subject::VCD_CODETABLE)
		
		expect do
			subject.decode(source, delta)
		end.to raise_exception(Protocol::HTTP::VCDiffError, message: be =~ /code table|Unsupported/)
	end

	it "rejects target-window source indicators" do
		delta = subject.encode(source, "other")
		delta.setbyte(5, subject::VCD_TARGET)
		
		expect do
			subject.decode(source, delta)
		end.to raise_exception(Protocol::HTTP::VCDiffError, message: be =~ /target windows|Unsupported/)
	end
	
	it "does not let a wrong base produce a normal representation" do
		target = "the quick red fox"
		delta = subject.encode(source, target)
		
		expect do
			subject.decode("the slow brown cat", delta)
		end.to raise_exception(Protocol::HTTP::VCDiffError)
	end
end

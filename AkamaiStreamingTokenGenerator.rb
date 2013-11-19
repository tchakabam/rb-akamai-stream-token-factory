#!/usr/bin/env ruby

# Generates (D-Type) access tokens for streaming edge servers for use in Akamai RTMP(E) auth'

# @author Stephan Hesse <disparat@gmail.com>

# Copyright Tape TV AG 2013

# For redistribution and usage rights, please contact the author(s)

require 'digest'

class AkamaiStreamingTokenGenerator

    def log(msg) 
        if @debug then
            puts msg
        end
    end

	def initialize(user_path, user_profile, user_pwd, time_stamp, time_window, debug=false)

		@user_path = user_path
		@user_profile = user_profile
		@user_pwd = user_pwd
		@time_stamp = time_stamp
		@time_window = time_window	
        @debug = debug

        log "path: " + @user_path
        log "profile: " + @user_profile
        log "password: " + @user_pwd
        log "time_stamp: " + @time_stamp.to_s
        log "time_window: " + @time_window.to_s

		@CHOICES64 = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j','k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't','u', 'v', 'w', 'x', 'y', 'z','A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J','K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T','U', 'V', 'W', 'X', 'Y', 'Z','0', '1', '2', '3', '4', '5', '6', '7', '8', '9','.', '/']
		
       	@ROT_BASE = 9
        @ENCRYPTED_LEN = 13;

        #Flag constants;
        @FLAG_IP       = 1
        @FLAG_PATH     = 2
        @FLAG_PROFILE  = 4
        @FLAG_PASSWD   = 8
        @FLAG_WINDOW   = 16
        @FLAG_PAYLOAD  = 32
        @FLAG_DURATION = 64

        @flags = 0
        @flags = @flags | @FLAG_PATH
        @flags = @flags | @FLAG_PROFILE
        @flags = @flags | @FLAG_PASSWD
        @flags = @flags | @FLAG_WINDOW
        @flags = @flags | @FLAG_DURATION
	end

	def generate_type_d

        #Create MD5 digest
		digest = Digest::MD5.new

        #Build time-window-based hash
        time_str = ""
		time_str << int32_to_custom_base64_str(@time_stamp, 1)
        time_str << '-'
		time_str << int32_to_custom_base64_str(@time_window, 1)
		time_str = fix_slash time_str

		log "Time-Window hash: " + time_str

        #Duration string
		duration_str = int32_to_custom_base64_str(@time_window, 1)

        log "Duration hash: " + duration_str

        #Create digest buffer
		md5_str = @user_path << time_str << @user_profile << @user_pwd << duration_str

        log "MD5 buffer: " + md5_str

		md5_str = digest.hexdigest(md5_str)

        log "MD5 digested: " + md5_str

		#Convert hex codes to characters
        digest_64 = ""
        i = 0
        while i < md5_str.length do
        	hexstr = md5_str.slice(i, 2) #slice next two chars
        	hexval = hexstr.to_i(16)
            log "ASCII code: " + hexval.to_s + " => " + hexval.chr
        	digest_64 << hexval.chr #append ASCII caracter of value
        	i += 2
        end

        log "Converted to characters: " + digest_64

        #Append the password
        digest_64 << @user_pwd  

        log "Password appended: " + digest_64

        #MD5 that again
 		md5_str = digest.hexdigest(digest_64)

        log "MD5 digested (again): " + md5_str

        #Encode the MD5 in base64
 		digest_64 = encode_md5 md5_str

        log "Akamai 64 encoded: " + digest_64

 		payload = ''
 		tokenType = 'd'

        #Build the actual token
 		token = build_token(tokenType, @flags, digest_64, time_str, @user_profile, payload, duration_str)

        log "Built token: " + token

        token
	end

	#Build token from buffers.  Note, newFlags is not used.
	def build_token(tType, newFlags, digested, timeBuf, prof, payl, durBuf)

        newToken = tType
        newToken << int32_to_custom_base64_str(@flags, 2)
        newToken << digested;

        if tType != 'a' then
            newToken << '-'
        end

        newToken << timeBuf

        if durBuf.length > 0  then
            newToken << '-'
            newToken << durBuf
        end

        newToken = fix_slash newToken 
        newToken << make_trailer(newToken, prof, payl, tType)
        newToken = fix_slash newToken

	end

    # Create trailer for token.
    def make_trailer(token, profile, payload, tokenType)
         
         trailer = ""
         obs_buf = ""

         if profile.length == 0 && payload.length == 0 then
         	trailer
         end

         if profile.length > 0 then
             trailer << '-'
             trailer << profile
         end

         if tokenType == 'a' then
             if payload.length > 0 
                trailer << '-'
                trailer << payload
             end
             obs_buf = obfuscate(token, trailer, 2, 13)
         else
            if payload.length > 0 then
                trailer << '-'
                i = 0
                while i < payload.length do
                	ch = payload[i].unpack('c') & 0xff
                	trailer << int32_to_custom_base64_str(ch, 2)
                	i += 1
                end
             end
             obs_buf = obfuscate(token, trailer, 3, 32)
         end

         obs_buf = fix_slash obs_buf
    end

    
    #Scramble string based on rot-13 derived algorithm.
    def obfuscate(token, trailer, startIndex, digestLen) 
        
        #temp var for token manipulation
        tempstr = "";
        e_digits = Array.new

        #eIndex - index into e_digits
        #index - index into token
   
   		eIndex = 0
   		index = 0
        while index < digestLen do
            tempstr = token.slice(index+startIndex, 1)
            val = custom_base64_str_to_int32(tempstr)
            e_digits[eIndex] = val % 10
            index += 1
            eIndex += 1
        end

        # Note: length not set as in java code.
        obfuscated = Array.new
        obfuscated[0] = trailer[0];
        obfString = ""
        index = 0

        while index < trailer.length do

            rot_val = @ROT_BASE + e_digits[index % digestLen]

            char = ""
            char << trailer[index]

            # Get code of character at index
            ch = char.unpack('c')[0]

            # "rotation" logic
            if ch >= 97 && ch <= 122 then
                ch = ch + rot_val
                if ch > 122 then
                    # extend the rotation into the capitals
                    # 'A' + ch - 'z' - 1
                    ch = 65 + ch - 122 - 1
                end
            elsif ch >= 65 && $ch <= 90 then
                ch = ch + rot_val
                if ch > 90 then
                    # extend the rotation into the digits
                    # '0' + ch - 'Z' - 1;
                    ch = 48 + ch - 90 - 1
                    #  see if we extended past all the digits
                    if ch > 57 then
                        # extend the rotation into the lowers
                        # 'a' + (ch - '9' - 1)
                        ch = 97 + ch - 57 - 1
                    end
                end
            elsif ch >= 48 && ch <= 57 then
                ch = ch + rot_val
                if ch > 57 then
                    # extend the rotation into the lowers
                    # 'a' + ch - '9' - 1;
                    ch = 97 + ch - 57 - 1
                end
            end

            # Assign to obfuscated string converting code to character
            obfuscated[index] = ch.chr;
            obfString << obfuscated[index] #FIXME: this us unhandy, should probably use pack()
            index += 1
        end

        # Fix slashes
        obfString = fix_slash(obfString)

    end

	def fix_slash input 
		input.gsub('/', '_')
	end

	def unfix_slash input 
		input.gsub('_', '/')
	end

	#Takes the MD5 digest from PHP and encodes it tobe compatible with Java generated token. 
    def encode_md5 md5_digested
        digest64 = ""
        i = 0
        while i < md5_digested.length do
           hexstr = md5_digested.slice(i, 2)
           hexval = hexstr.to_i(16)
           digest64 << int32_to_custom_base64_str(hexval, 2)
           i += 2
        end
        digest64 
    end

    # Converts 64 based encoding to integer (32).    
    def make_int c_in
    	c = ""
    	c << c_in
    	#log c
    	ord = 0
    	cun = c.unpack('c')[0]
    	#log "__"
    	#log cun
        if cun >= 97 && cun <= 122 then
           ord = cun - 97
        elsif cun >= 65 && cun <= 90 then
           ord = cun - 39 # - 65 + 26
        elsif cun >= 48 && cun <= 57 then
           ord = cun + 4 # - 48 + 52
        elsif cun == 46 then
           ord = 62
        else
           ord = 63
        end
    end

    #Convert from encoded string to a number
    def custom_base64_str_to_int32 buffer 
        result = 0
        i = 0
        while i < buffer.length do
            result = result * 64 + make_int(buffer[i])
            i += 1
        end
        result
    end

	#Converts integer (32) values to character strings using lookup array.
	def int32_to_custom_base64_str(input, min_value)
		#log input

        val = input
        result = ""

        while val > 63 do
            result << @CHOICES64[val % 64]
            val = val / 64
        end

        #Pick up last bit.
        result << @CHOICES64[val % 64]

        #Pad result to minimum length
        while result.length < min_value do
            result << @CHOICES64[0];
        end

        result = result.reverse
	end
end

# Testbed
if __FILE__ == $0

	path = "/mycontentpath.edgefcs.net/ondemand"
	profile = "myprofile"
	password = "mypassword"
	time = Time.now.to_i #seconds
	#time = 1384348052
    window = 86400 #seconds (here: 24 hours)

	gen = AkamaiStreamingTokenGenerator.new(path, profile, password, time, window, true)
    token = gen.generate_type_d
	gen.log token
	
end
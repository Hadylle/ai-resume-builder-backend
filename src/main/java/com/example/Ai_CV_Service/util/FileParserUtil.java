package com.example.Ai_CV_Service.util;

import org.apache.tika.parser.AutoDetectParser;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.sax.BodyContentHandler;
import org.apache.tika.metadata.Metadata;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

@Component
public class FileParserUtil {
    
    private final AutoDetectParser parser = new AutoDetectParser();

    public String extractText(MultipartFile file) throws Exception {
        BodyContentHandler handler = new BodyContentHandler(-1); // -1 for unlimited length
        Metadata metadata = new Metadata();
        ParseContext context = new ParseContext();
        
        parser.parse(file.getInputStream(), handler, metadata, context);
        return handler.toString();
    }
}
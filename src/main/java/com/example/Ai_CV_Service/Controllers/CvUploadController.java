package com.example.Ai_CV_Service.Controllers;

import com.example.Ai_CV_Service.Services.CvAiService;
import com.example.Ai_CV_Service.util.FileParserUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/cv")
public class CvUploadController {

    @Autowired
    private FileParserUtil fileParserUtil;

    @Autowired
    private CvAiService cvAiService;

    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file) {
        try {
            String text = fileParserUtil.extractText(file);
            return cvAiService.analyzeRawText(text);
        } catch (Exception e) {
            return "Error processing file: " + e.getMessage();
        }
    }
}

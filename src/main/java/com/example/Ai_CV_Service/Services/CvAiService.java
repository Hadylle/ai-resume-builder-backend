package com.example.Ai_CV_Service.Services;

import com.example.Ai_CV_Service.model.CvInfo;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.stereotype.Service;

@Service
public class CvAiService {

    private final ChatClient chatClient;

    public CvAiService(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    public String analyzeRawText(String extractedText) {
        String prompt = "Extract key CV information and summarize the candidate:\n\n" + extractedText;
        return chatClient.prompt().user(prompt).call().content(); // ✅ correct usage
    }

    public String analyze(CvInfo cvInfo) {
        String prompt = String.format(
                "Here's a candidate CV. Provide a brief summary and evaluate strengths:\n\n" +
                        "Name: %s\nEducation: %s\nExperience: %s\nSkills: %s\nCertifications: %s",
                cvInfo.getName() != null ? cvInfo.getName() : "Unknown",
                cvInfo.getEducation() != null ? cvInfo.getEducation() : "Not provided",
                cvInfo.getExperience() != null ? cvInfo.getExperience() : "Not provided",
                cvInfo.getSkills() != null ? cvInfo.getSkills() : "Not provided",
                cvInfo.getCertifications() != null ? cvInfo.getCertifications() : "Not provided"
        );

        return chatClient.prompt().user(prompt).call().content(); // ✅
    }
}

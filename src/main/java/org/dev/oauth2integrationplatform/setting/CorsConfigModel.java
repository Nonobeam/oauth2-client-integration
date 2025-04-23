package org.dev.oauth2integrationplatform.setting;

import lombok.Data;
import org.springframework.stereotype.Component;

import java.util.List;

@Data
@Component
public class CorsConfigModel {
  private List<String> allowCors;
}

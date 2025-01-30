package org.example.safecode.models.response;

import lombok.*;

import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Getter
@Setter
@Builder
public class Recommendation {
  private int id;
  private String type;
  private List<String> recommendations;
}

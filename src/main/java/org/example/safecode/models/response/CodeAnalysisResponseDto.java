package org.example.safecode.models.response;

import lombok.*;

import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Getter
@Setter
@Builder
public class CodeAnalysisResponseDto {
  private List<Recommendation> recommendations;
}

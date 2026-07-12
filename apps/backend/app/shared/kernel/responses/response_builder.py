from app.shared.kernel.responses.api_response import ApiResponse


class ResponseBuilder:

    @staticmethod
    def success(message: str, data=None) -> ApiResponse:
        return ApiResponse(
            success=True,
            message=message,
            data=data,
        )
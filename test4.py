from fastapi import APIRouter

router = APIRouter(prefix="/test", tags=["test"])

@router.get("/")
def test():
    return {"message": "test success"}

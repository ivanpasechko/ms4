from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field, Relationship

class LoginHistory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", ondelete="CASCADE")
    user_agent: Optional[str] = Field(default=None)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    user: Optional["User"] = Relationship(back_populates="history")

class LoginHistoryRead(SQLModel):
    user_id: int
    user_agent: Optional[str]
    timestamp: datetime
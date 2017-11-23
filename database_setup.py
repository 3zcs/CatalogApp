import sys
import os
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class Category(Base):
    __tablename__ = 'category'

    name = Column(String(100), nullable=False)
    id = Column(Integer, primary_key=True)


class User(Base):
    __tablename__ = 'user'

    name = Column(String(100), nullable=False)
    email = Column(String(140), nullable=False)
    id = Column(Integer, primary_key=True)


class Item(Base):
    __tablename__ = 'item'

    name = Column(String(100), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    

engine = create_engine('sqlite:///category.db')

Base.metadata.create_all(engine)


from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from datetime import datetime
import pytz

Base = declarative_base()


class User(Base):
    """Setting up user table"""
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return{
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'picture': self.picture,
         }


class Catalog(Base):
    """Setting up Catalogs table"""
    __tablename__ = "catalog"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    item = relationship('Item', cascade='all, delete-orphan')

    @property
    def serialize(self):
        """Return object data in serializeable format"""
        return {
            'id': self.id,
            'name': self.name,
        }


class Item(Base):
    """Setting up Item table"""
    __tablename__ = "item"
    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    date = Column(DateTime, default=datetime.now(
        tz=pytz.UTC).astimezone(pytz.timezone('Asia/Calcutta')))
    description = Column(String, nullable=False)
    catalog_id = Column(Integer, ForeignKey('catalog.id'))
    catalog = relationship(Catalog)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in serializeable format"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'catalog-id': self.catalog_id,
        }


engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.create_all(engine)

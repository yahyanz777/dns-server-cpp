#include <gtest/gtest.h>

#include "DnsQuestion.hpp"
#include "BytePacketBuffer.hpp"
#include <cstdint>


namespace {

TEST(DnsQuestionTest, ParsesARecordQuestion)
{
	// www.example.com, followed by QTYPE=A and QCLASS=IN.
	BytePacketBuffer buffer{
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm', 0,
		0, 1,
		0, 1};
	DnsQuestion question = DnsQuestion::read(buffer);

	EXPECT_EQ(question.getName(), "www.example.com");
	EXPECT_EQ(question.getType(), QuestionType::A);
	EXPECT_EQ(question.getClass(), 1);
}

TEST(DnsQuestionTest, ParsesRootQuestion)
{
	BytePacketBuffer buffer{0, 0, 28, 0, 1};

	DnsQuestion question = DnsQuestion::read(buffer);

	EXPECT_EQ(question.getName(), ".");
	EXPECT_EQ(question.getType(), QuestionType::AAAA);
	EXPECT_EQ(question.getClass(), 1);
}

TEST(DnsQuestionTest, RejectsTruncatedQuestion)
{
	BytePacketBuffer buffer{
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a'};

	EXPECT_THROW(DnsQuestion::read(buffer), std::out_of_range);
}

TEST(DnsQuestionTest, WritesAndReadsQuestions)
{
	DnsQuestion q1("google.com", QuestionType::A, 1);
	DnsQuestion q2("mail.google.com", QuestionType::MX, 1);
	DnsQuestion q3(".", QuestionType::SOA, 1);

	BytePacketBuffer buffer;
	q1.write(buffer);
	q2.write(buffer);
	q3.write(buffer);

	buffer.seek(0);
	DnsQuestion r1 = DnsQuestion::read(buffer);
	EXPECT_EQ(r1.getName(), "google.com");
	EXPECT_EQ(r1.getType(), QuestionType::A);
	EXPECT_EQ(r1.getClass(), 1);

	DnsQuestion r2 = DnsQuestion::read(buffer);
	EXPECT_EQ(r2.getName(), "mail.google.com");
	EXPECT_EQ(r2.getType(), QuestionType::MX);
	EXPECT_EQ(r2.getClass(), 1);

	DnsQuestion r3 = DnsQuestion::read(buffer);
	EXPECT_EQ(r3.getName(), ".");
	EXPECT_EQ(r3.getType(), QuestionType::SOA);
	EXPECT_EQ(r3.getClass(), 1);
}

} 

